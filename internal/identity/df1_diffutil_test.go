package identity

// Minimal EXPECTED-DIFFERENCE allowlist helper for the DF1 identity fold differential
// (test-only). Mirrors internal/libconformance/diffutil_test.go; duplicated rather than
// shared because the two live in different packages and the type is a few lines.

import (
	"sort"
	"testing"
)

type expectedDiff struct {
	key    string
	reason string
	hits   int
}

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

func (a *allowlist) allows(key string) bool {
	r, ok := a.rows[key]
	if ok {
		r.hits++
	}
	return ok
}

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
