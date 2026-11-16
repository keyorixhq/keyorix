// fallback_limiter_bounded_fuzz_test.go — FuzzAuthFallbackLimiterBounded (RL1).
//
// The in-memory authFallbackLimiter (auth_budget.go) is the single structure
// every per-source auth budget (login / password-reset / SSO-begin, keyed on
// core.CanonicalIP) falls back to when the login_attempts store is unavailable.
// Under storage degradation an unauthenticated flood from many distinct sources
// drives many distinct KEYS into it, so its memory MUST stay bounded by its cap,
// not by the number of distinct keys ever seen.
//
// TestLoginBudgetFallback_BoundedUnderManyDistinctIPs already asserts
// f.size() <= cap. size() reads lru.Len() — the VISIBLE key count. It is blind to
// the two INDEX maps (byID, byStored): an eviction (or a release path) that drops
// a key from the LRU but forgets to delete that key's attempts from byID/byStored
// leaks memory that grows with the distinct-key count while size() stays pinned at
// the cap — a memory DoS no size() assertion can ever catch. This target closes
// that gap with a metamorphic/structural oracle, fuzzing an adversarial program of
// reserve/mirror/tryReserve/release/releaseMirror/clear/count over up to 65 536
// distinct keys and asserting, after every program, that the limiter's index maps
// are bounded by the cap and hold EXACTLY one entry per live attempt.
//
// resguard: the memory meters are enabled (Probe over a PERSISTENT limiter across
// inputs) and Drift watches cross-input live-heap growth as a defence-in-depth
// backstop — a leak the structural invariant somehow missed would still surface as
// a rising heap floor. No disk/net/sleep seams (none apply to an in-memory map).
// The LOAD-BEARING, red/green-proven oracle here is the structural invariant;
// Drift is the RSG1-validated cross-input watcher, reused unchanged.
//
// What this target does NOT verify:
//   - It does not exercise the real storage-degradation wiring (budgetReserve's
//     fallback path) — it drives the limiter directly. Reachability of the
//     fallback from a live caller is traced in the RL1 report, not asserted here.
//   - It does not assert time-window pruning correctness (it holds `now` fixed so
//     eviction is purely LRU, the hardest case for the key cap); the window-prune
//     path is covered by the existing fallback unit tests.
//   - It does not prove the counter cannot be reset by an attacker action — that
//     is a reachability claim (clear/release require a delivered session), argued
//     in the report; here clear/release are exercised only for memory-bound
//     soundness, not as an authorization oracle.
package core

import (
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

const (
	fbMaxKeys   = 32
	fbMaxPerKey = 4
)

var (
	fbWindow = time.Hour
	fbBase   = time.Unix(1_700_000_000, 0).UTC()
)

// fbStats is a snapshot of the limiter's internal bookkeeping.
type fbStats struct {
	keys              int
	idEntries         int
	storedEntries     int
	maxAttemptsPerKey int
	totalAttempts     int
}

// realFallbackStats reads the real limiter's structure under its own lock.
func realFallbackStats(f *authFallbackLimiter) fbStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := fbStats{keys: f.lru.Len(), idEntries: len(f.byID), storedEntries: len(f.byStored)}
	for e := f.lru.Front(); e != nil; e = e.Next() {
		n := len(e.Value.(*authFallbackEntry).attempts)
		s.totalAttempts += n
		if n > s.maxAttemptsPerKey {
			s.maxAttemptsPerKey = n
		}
	}
	return s
}

// checkFallbackBounded is the RL1 memory-bound oracle. Every structure the
// limiter keeps must be bounded by the CAP, and the id index must hold exactly one
// entry per live attempt — not grow with the number of distinct keys inserted.
func checkFallbackBounded(s fbStats, maxKeys, maxPerKey int) error {
	if s.keys > maxKeys {
		return fmt.Errorf("BOUND keys: %d tracked > maxKeys %d", s.keys, maxKeys)
	}
	if s.maxAttemptsPerKey > maxPerKey {
		return fmt.Errorf("BOUND per-key: a key holds %d attempts > maxPerKey %d", s.maxAttemptsPerKey, maxPerKey)
	}
	// The tight invariant: byID has exactly one entry per currently-live attempt.
	// An eviction/release that forgets to clean byID breaks this immediately.
	if s.idEntries != s.totalAttempts {
		return fmt.Errorf("INDEX LEAK byID: %d id entries but %d live attempts — eviction/forget did not clean the id index (memory grows with distinct-key count)", s.idEntries, s.totalAttempts)
	}
	if s.idEntries > maxKeys*maxPerKey {
		return fmt.Errorf("BOUND byID: %d id entries > maxKeys*maxPerKey %d", s.idEntries, maxKeys*maxPerKey)
	}
	if s.storedEntries > s.totalAttempts {
		return fmt.Errorf("INDEX LEAK byStored: %d stored-mirror entries > %d live attempts", s.storedEntries, s.totalAttempts)
	}
	return nil
}

// runFallbackProgram drives an adversarial op sequence decoded from data against
// f, using up to 65 536 distinct keys (>> maxKeys) to stress eviction.
func runFallbackProgram(f *authFallbackLimiter, data []byte) {
	i := 0
	next := func() byte {
		if i >= len(data) {
			return 0
		}
		b := data[i]
		i++
		return b
	}
	var ids []uint
	var stored []uint
	for i < len(data) {
		op := next() % 7
		key := "k" + itoa(int(uint16(next())<<8|uint16(next())))
		switch op {
		case 0:
			ids = append(ids, f.reserve(key, fbBase, fbWindow, fbMaxPerKey))
		case 1:
			sid := uint(next()) + 1
			f.mirror(key, fbBase, fbWindow, fbMaxPerKey, sid)
			stored = append(stored, sid)
		case 2:
			f.tryReserve(key, fbBase, fbWindow, fbMaxPerKey, fbMaxPerKey)
		case 3:
			if len(ids) > 0 {
				f.release(ids[int(next())%len(ids)])
			}
		case 4:
			if len(stored) > 0 {
				f.releaseMirror(stored[int(next())%len(stored)])
			}
		case 5:
			f.clear(key)
		case 6:
			f.count(key, fbBase.Add(-fbWindow), true)
		}
	}
}

func FuzzAuthFallbackLimiterBounded(f *testing.F) {
	lim := newAuthFallbackLimiter(fbMaxKeys)
	probe := resguard.New(f, resguard.Options{})

	// Seeds: a tiny mixed program, and one that floods many distinct keys.
	f.Add([]byte{0, 0, 1, 1, 0, 2, 2, 0, 3, 6, 0, 4})
	flood := make([]byte, 0, 3*500)
	for k := range 500 {
		flood = append(flood, 0, byte(k>>8), byte(k)) // reserve distinct key k
	}
	f.Add(flood)

	f.Fuzz(func(t *testing.T, data []byte) {
		c := probe.Measure(len(data), func() {
			runFallbackProgram(lim, data)
		})
		if r := probe.CheckDrift(c); r != "" {
			t.Fatal(r)
		}
		if err := checkFallbackBounded(realFallbackStats(lim), fbMaxKeys, fbMaxPerKey); err != nil {
			t.Fatalf("%v (after a %d-byte program; limiter size=%d)", err, len(data), lim.size())
		}
	})
}
