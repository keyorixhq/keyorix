// fallback_limiter_bounded_redgreen_test.go — red/green proof for the RL1
// index-leak oracle (checkFallbackBounded). GREEN: the REAL production
// authFallbackLimiter, flooded with many distinct keys, keeps its byID index ==
// live attempts. RED: a structurally-identical limiter whose eviction forgets to
// clean byID (the exact omission f.size() cannot detect) leaks one id entry per
// distinct key, and the oracle fires. No production code is edited.
package core

import (
	"container/list"
	"testing"
)

// leakyFallback replicates authFallbackLimiter's LRU + byID index but its
// eviction drops a key from the LRU WITHOUT cleaning that key's byID entries —
// the forget-on-evict omission a size()-only assertion is blind to.
type leakyFallbackEntry struct {
	key      string
	attempts []uint
}

type leakyFallback struct {
	maxKeys int
	lru     *list.List
	byKey   map[string]*list.Element
	byID    map[uint]string
	nextID  uint
}

func newLeakyFallback(maxKeys int) *leakyFallback {
	return &leakyFallback{
		maxKeys: maxKeys,
		lru:     list.New(),
		byKey:   map[string]*list.Element{},
		byID:    map[uint]string{},
	}
}

func (f *leakyFallback) reserve(key string, maxPerKey int) {
	el, ok := f.byKey[key]
	if !ok {
		for f.lru.Len() >= f.maxKeys {
			oldest := f.lru.Back()
			oe := oldest.Value.(*leakyFallbackEntry)
			// BUG (the whole point): forget the key from byKey/lru but NOT its
			// attempts from byID — size() still reports <= maxKeys, byID grows.
			delete(f.byKey, oe.key)
			f.lru.Remove(oldest)
		}
		e := &leakyFallbackEntry{key: key}
		el = f.lru.PushFront(e)
		f.byKey[key] = el
	} else {
		f.lru.MoveToFront(el)
	}
	e := el.Value.(*leakyFallbackEntry)
	f.nextID++
	id := f.nextID
	e.attempts = append(e.attempts, id)
	f.byID[id] = e.key
	if len(e.attempts) > maxPerKey {
		delete(f.byID, e.attempts[0]) // per-key trim is correct; only eviction leaks
		e.attempts = e.attempts[1:]
	}
}

func leakyStats(f *leakyFallback) fbStats {
	s := fbStats{keys: f.lru.Len(), idEntries: len(f.byID)}
	for e := f.lru.Front(); e != nil; e = e.Next() {
		n := len(e.Value.(*leakyFallbackEntry).attempts)
		s.totalAttempts += n
		if n > s.maxAttemptsPerKey {
			s.maxAttemptsPerKey = n
		}
	}
	return s
}

func TestRedGreen_FallbackIndexLeak(t *testing.T) {
	const distinct = 2000 // >> fbMaxKeys, forcing many evictions

	// GREEN — the real limiter cleans byID on eviction.
	real := newAuthFallbackLimiter(fbMaxKeys)
	for k := range distinct {
		real.reserve("k"+itoa(k), fbBase, fbWindow, fbMaxPerKey)
	}
	rs := realFallbackStats(real)
	if rs.keys > fbMaxKeys {
		t.Fatalf("GREEN precondition: real size %d > cap %d", rs.keys, fbMaxKeys)
	}
	if err := checkFallbackBounded(rs, fbMaxKeys, fbMaxPerKey); err != nil {
		t.Fatalf("GREEN failed: real limiter must stay bounded after %d distinct keys: %v", distinct, err)
	}

	// RED — the leaky limiter keeps size() bounded but leaks byID.
	leaky := newLeakyFallback(fbMaxKeys)
	for k := range distinct {
		leaky.reserve("k"+itoa(k), fbMaxPerKey)
	}
	ls := leakyStats(leaky)
	if ls.keys > fbMaxKeys {
		t.Fatalf("RED precondition: leaky size %d > cap %d (size() should still be bounded)", ls.keys, fbMaxKeys)
	}
	if err := checkFallbackBounded(ls, fbMaxKeys, fbMaxPerKey); err == nil {
		t.Fatalf("RED failed: the index-leak oracle must fire; leaky byID=%d totalAttempts=%d size=%d",
			ls.idEntries, ls.totalAttempts, ls.keys)
	}
}
