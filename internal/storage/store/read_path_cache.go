// read_path_cache.go — the ONE place in this package where a read-path cache
// entry is written. Spec: docs/specs/read-path-cache-ordering.md (GUARD-6).
//
// # Why this file exists
//
// Every generation-validated read cache has the same three parts: a cheap
// generation (stamp) read, an expensive data load, and a map from a key to
// (stamp, value). A miss reads both and stores them together; a hit re-reads
// the stamp live and serves the cached value only when the fresh stamp equals
// the stored one. That shape is correct — but only under one ordering
// constraint, and nothing about the shape enforces it:
//
//	BUGGY: data first, stamp second          CORRECT: stamp first, data second
//	  v := load()                              g := gen()        -> G_before
//	  <a write commits>                        <a write commits>
//	  g := gen()      -> G_after               v := load()       -> V_after
//	  cache[k] = (G_after, v)  <- V_before!    cache[k] = (G_before, V_after)
//
// In the buggy ordering the entry is born self-consistent and WRONG: the next
// hit reads G_after live, it matches, and the pre-change answer is served —
// not for a bounded TTL (there is none) but until some unrelated write bumps
// that generation again. In the correct ordering the worst case is an entry
// stamped G_before holding V_after: pessimistically stale, so it never hits,
// and the only cost is a wasted map slot. The failure is asymmetric — one
// ordering fails open and silently, the other fails to a cache miss.
//
// That exact defect was found in BOTH of PERF-3's caches, written
// independently days apart, each with a full test file including cross-replica
// Postgres cases: a revoked permission kept authorizing (#2767,
// TestRoleSetHasPermission_RevokeDuringResolveIsNotCachedStale) and a rotated
// secret kept returning its pre-rotation version (#2764,
// TestGetLatestSecretVersion_RotationDuringResolveIsNotCachedStale). It is not
// hard to state; it is hard to NOTICE, because the buggy code looks fine and
// every test that does not race a write through the window passes. So the
// ordering is no longer something a reviewer has to spot: there is exactly one
// function that writes an entry, it reads the generation before it is handed
// the loader, and read_path_cache_guard_test.go fails the build if anything
// else writes one.
//
// # The three rules a generation must satisfy
//
// Ordering is necessary, not sufficient. All three of these were also found
// live, in the same two PRs (#2764 4b31a9d6, #2767 34495c0d):
//
//  1. DERIVE THE STAMP FROM THE CACHED COLUMNS. A timestamp is a stamp only
//     for writers that advance it. `secret_nodes.updated_at` alone missed
//     TryIncrementSecretNodeReadCount's UpdateColumn write, so a warm entry
//     served read_count=0 forever and RotateSecret's read-modify-write wrote
//     that stale zero back — a fresh budget for a burn-after-N-reads secret.
//  2. NO CLOCK IN A STAMP FOR A TABLE WRITTEN IN A TIGHT LOOP. Resolution ties
//     are indistinguishable from "nothing changed":
//     storeNextSecretVersion's retry loop re-read its own stale cached answer
//     and burned all 20 attempts against the unique index.
//  3. A STAMP MUST BE DETERMINISTIC. A clock- or randomness-derived stamp is
//     invisible to every state-comparison oracle in this repo — a
//     time.Now()+random generation value broke FuzzStorageFaultOperations'
//     oracle (a) on seven seeds.
//
// Rule 3 is why cacheGeneration below is a constrained type rather than `any`,
// and rules 1 and 2 are why each site declares its OWN generation type naming
// the columns it covers (see secret_metadata_cache.go and
// role_permission_cache.go). Writer coverage for rule 1 is machine-checked by
// secret_metadata_cache_generation_test.go.
//
// # What this file does NOT do
//
//   - No TTL, no push invalidation, no cross-process cache. Unchanged from
//     docs/specs/read-path-caching.md's reasoning.
//   - No deep copy of V. A call site's `load` must hand over a value it does
//     not retain, and must copy on the way out to its own caller; the helper
//     stores and returns exactly the value it was given.
//   - Nothing here changes an authorization decision. A cache hit flows
//     through the same Authorize* call a miss does; only the DATA is cached.
package store

import (
	"context"
	"sync"
)

// cacheGeneration constrains a cache's generation type. It is `comparable`
// because the helper compares stamps with `==`, PLUS a marker method declared
// in this package.
//
// The marker is load-bearing, not decoration: `comparable` alone would admit
// `time.Time`, and `==` on a time.Time also compares the monotonic reading and
// the *time.Location pointer, so two reads of the SAME column can compare
// unequal. A cache whose stamps never compare equal never hits — a pure
// performance failure, invisible to every correctness test, exactly the kind
// of thing that survives for a year unnoticed. The marker makes time.Time not
// satisfy this constraint, so that mistake does not compile; a timestamp-based
// generation must canonicalise to int64 nanoseconds on the way in instead
// (Postgres stores timestamptz at microsecond precision, so the read-back
// value is stable and this loses nothing the column had).
type cacheGeneration interface {
	comparable
	isCacheGeneration()
}

// genGeneration reads the current generation live. (stamp, true, nil) on
// success; (_, false, nil) when the row the stamp lives on does not exist;
// (_, _, err) on any DB error. Both of the latter two are a MISS — never
// "assume unchanged" (see cachedRead's contract).
type genGeneration[G cacheGeneration] func(context.Context) (G, bool, error)

type genCacheEntry[G cacheGeneration, V any] struct {
	stamp G
	value V
}

// genCache is the only cache container in this package. Its entries are
// written ONLY by cachedRead/cachedReadSameRow below — enforced by
// read_path_cache_guard_test.go, not by convention.
type genCache[K comparable, G cacheGeneration, V any] struct {
	mu      sync.Mutex
	entries map[K]genCacheEntry[G, V]
}

func newGenCache[K comparable, G cacheGeneration, V any]() *genCache[K, G, V] {
	return &genCache[K, G, V]{entries: make(map[K]genCacheEntry[G, V])}
}

// get is read-only and therefore unrestricted — it cannot create staleness.
func (c *genCache[K, G, V]) get(key K) (genCacheEntry[G, V], bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	return e, ok
}

// store writes an entry. The guard test fails the build on any call to this
// from outside this file: a stamp-and-value pair written anywhere else is the
// bug class this file exists to make impossible.
func (c *genCache[K, G, V]) store(key K, stamp G, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = genCacheEntry[G, V]{stamp: stamp, value: value}
}

// drop removes an entry. Deliberately NOT restricted by the guard: dropping an
// entry can only ever cost a future cache miss, never serve a stale value, so
// it is not part of the bug class. (Stated here so the guard's narrower scope
// reads as considered rather than overlooked.)
func (c *genCache[K, G, V]) drop(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// size reports the number of live entries; read-only, for tests and metrics.
func (c *genCache[K, G, V]) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// probe is the ONLY place a generation is read on a read path, and it reads it
// BEFORE its caller can possibly call a loader — that is how the ordering
// constraint is enforced structurally rather than remembered.
//
// Returns:
//
//	value, true,  stamp, true   a confirmed-current hit
//	_,     false, stamp, true   a miss, with a stamp read strictly before any load
//	_,     false, _,     false  the generation read failed or found no row: a
//	                            miss that must NOT be cached under any stamp
func probe[K comparable, G cacheGeneration, V any](
	ctx context.Context, cache *genCache[K, G, V], key K, gen genGeneration[G],
) (value V, hit bool, stamp G, stampUsable bool) {
	stamp, found, err := gen(ctx)
	if err != nil || !found {
		var zeroG G
		var zeroV V
		return zeroV, false, zeroG, false
	}
	if e, ok := cache.get(key); ok && e.stamp == stamp {
		return e.value, true, stamp, true
	}
	var zeroV V
	return zeroV, false, stamp, true
}

// cachedRead serves key from cache when a fresh generation read confirms the
// cached entry's stamp, and otherwise loads live. Use this whenever the
// generation lives somewhere OTHER than the row(s) load returns; for the
// same-row case use cachedReadSameRow, which says so explicitly.
//
// Contract, in this order, with no code path that can reorder it:
//
//  1. The generation is read FIRST — before the cache is consulted, and
//     therefore unconditionally before load. One read serves both the hit
//     check and the stamp an entry is stored under.
//  2. A hit is served only on a successful, found, EQUAL generation read. A
//     gen error, or found==false (the row is gone / soft-deleted), is a MISS.
//     Fail closed: never serve a cached value over a check that itself failed.
//  3. On a miss, load runs and its result is returned.
//  4. The entry is stored only when the generation read succeeded and found a
//     row, under the stamp from step 1. No path stores a stamp read after
//     load.
//  5. A load error DROPS the key and propagates. Dropping is always safe (it
//     costs a future miss) and is what stops a deleted row being served.
//
// load returning a nil pointer with NO error is how a call site caches a
// confirmed negative ("this generation has no such row") — the helper stores
// it like any other value.
func cachedRead[K comparable, G cacheGeneration, V any](
	ctx context.Context,
	cache *genCache[K, G, V],
	key K,
	gen genGeneration[G],
	load func(context.Context) (V, error),
) (V, error) {
	cached, hit, stamp, stampUsable := probe(ctx, cache, key, gen)
	if hit {
		return cached, nil
	}
	value, err := load(ctx)
	if err != nil {
		cache.drop(key)
		var zero V
		return zero, err
	}
	if stampUsable {
		cache.store(key, stamp, value)
	}
	return value, nil
}

// cachedReadSameRow is cachedRead for the ONE case where the ordering
// constraint does not apply: the generation is a column of the very row load
// returns, so a single query yields both atomically and there is no window
// between them for a write to commit into. load therefore returns the stamp
// alongside the value, and that stamp — not a separately read one — is what
// the entry is stored under.
//
// This variant exists so "this site is the same-row case" is something the
// code SAYS rather than something a reviewer has to re-derive. It cannot be
// misused for a cross-row generation: there would be no stamp to return from
// the loaded row.
//
// gen is still required, and still read before anything else, because a HIT
// must be validated against a live stamp without paying for the full load.
func cachedReadSameRow[K comparable, G cacheGeneration, V any](
	ctx context.Context,
	cache *genCache[K, G, V],
	key K,
	gen genGeneration[G],
	load func(context.Context) (V, G, error),
) (V, error) {
	cached, hit, _, _ := probe(ctx, cache, key, gen)
	if hit {
		return cached, nil
	}
	value, loadedStamp, err := load(ctx)
	if err != nil {
		cache.drop(key)
		var zero V
		return zero, err
	}
	cache.store(key, loadedStamp, value)
	return value, nil
}

// cachedHit is probe's hit check with nothing else — the read-only "is this
// key currently served from cache" question, for the fail-closed tests and
// for any caller that must not pay for a live load. It goes through probe for
// the same reason everything else does: a second, hand-written copy of the
// hit check is a second place the rules can be got wrong.
func cachedHit[K comparable, G cacheGeneration, V any](
	ctx context.Context, cache *genCache[K, G, V], key K, gen genGeneration[G],
) (V, bool) {
	value, hit, _, _ := probe(ctx, cache, key, gen)
	return value, hit
}

// invalidateCachedRead drops key from cache. Exported within the package (as
// opposed to store, which the guard restricts to this file) because, per
// drop's own comment, eviction cannot produce a stale read.
func invalidateCachedRead[K comparable, G cacheGeneration, V any](cache *genCache[K, G, V], key K) {
	cache.drop(key)
}
