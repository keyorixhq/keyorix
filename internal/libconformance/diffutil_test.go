package libconformance

// Shared helpers for the DF1 cross-library parser-differential fuzzers. Everything
// here is test-only (the package has no non-test code by charter — see doc.go).
//
// The common shape of every DF1 oracle: feed ONE input to two or more independent
// readings, derive a *canonical* comparison value from each, and fail on a
// disagreement that is not on that oracle's EXPECTED-DIFFERENCE allowlist. A
// documented, intentional library difference is recorded in the allowlist with a
// reason — never suppressed silently — and a companion Test<Oracle>AllowlistNoDead
// test fails if an allowlist key never fires across the seed corpus, so a stale
// entry cannot hide a regression.

import (
	"fmt"
	"sort"
	"testing"
)

// expectedDiff is one row of an oracle's EXPECTED-DIFFERENCE allowlist: a key that
// classifies a disagreement, the human reason it is intentional, and a hit counter
// the dead-entry test reads.
type expectedDiff struct {
	key    string
	reason string
	hits   int
}

// allowlist indexes expectedDiff rows by key and records which keys fired.
type allowlist struct {
	rows map[string]*expectedDiff
}

func newAllowlist(rows ...expectedDiff) *allowlist {
	m := make(map[string]*expectedDiff, len(rows))
	for i := range rows {
		r := rows[i]
		if _, dup := m[r.key]; dup {
			panic("duplicate allowlist key: " + r.key)
		}
		m[r.key] = &r
	}
	return &allowlist{rows: m}
}

// allows reports whether key is an accepted, documented difference. It records a hit
// so the dead-entry test can see the key fired.
func (a *allowlist) allows(key string) bool {
	r, ok := a.rows[key]
	if ok {
		r.hits++
	}
	return ok
}

// assertNoDeadEntries fails if any allowlist key was never hit while replaying the
// oracle over its seeds. A dead entry is a claim ("this difference is intentional and
// occurs") with nothing exercising it — exactly the stale-skip shape CLAUDE.md warns
// about — so it must be removed or its seed restored.
func (a *allowlist) assertNoDeadEntries(t *testing.T) {
	t.Helper()
	keys := make([]string, 0, len(a.rows))
	for k := range a.rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if a.rows[k].hits == 0 {
			t.Errorf("DEAD ALLOWLIST ENTRY %q (reason %q): never fired over the seed corpus; "+
				"remove it or add a seed that exercises it", k, a.rows[k].reason)
		}
	}
}

// diffError formats a differential failure uniformly across oracles.
func diffError(oracle, detail string, a, b any) string {
	return fmt.Sprintf("DIFFERENTIAL [%s]: %s\n  reading-A=%#v\n  reading-B=%#v", oracle, detail, a, b)
}
