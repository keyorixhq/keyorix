package storage

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func held(keys ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// TestCheckNamedLockOrder_Calibration: green on every nesting the core suite
// performs today (observed by tracing), red on each inversion shape.
func TestCheckNamedLockOrder_Calibration(t *testing.T) {
	for _, ok := range []struct {
		held []string
		key  string
	}{
		{nil, "last-admin-guard"},
		{[]string{"dual-control-approval:request:7"}, "sod-grant:user:3"},
		{[]string{"last-admin-guard"}, "project-admin-guard:5"},
		{[]string{"last-admin-guard", "project-admin-guard:5"}, "project-admin-guard:9"},
		{[]string{"project-admin-guard:5"}, "sod-grant:user:1"},
		{[]string{"project-membership:2:3"}, "sod-grant:user:3"},
		{[]string{"project-membership:2:3"}, "project-admin-guard:2"},
		{[]string{"sod-grant:group:4"}, "sod-grant:user:1"},
		{[]string{"sod-grant:user:1", "sod-grant:user:2"}, "sod-grant:user:10"}, // numeric, not lexical
	} {
		require.NoErrorf(t, CheckNamedLockOrder(held(ok.held...), ok.key), "held %v, acquire %s", ok.held, ok.key)
	}
	for _, bad := range []struct {
		held []string
		key  string
	}{
		{[]string{"project-admin-guard:5"}, "last-admin-guard"},
		{[]string{"sod-grant:user:1"}, "project-membership:2:1"},
		{[]string{"sod-grant:user:3"}, "sod-grant:group:4"},
		{[]string{"project-admin-guard:9"}, "project-admin-guard:5"},
		{[]string{"sod-grant:user:10"}, "sod-grant:user:9"},
		{nil, "some-new-family:1"},
		{[]string{"some-new-family:1"}, "sod-grant:user:1"},
	} {
		require.Errorf(t, CheckNamedLockOrder(held(bad.held...), bad.key), "held %v, acquire %s must be rejected", bad.held, bad.key)
	}
}

// TestNamedLockOrder_PrefixesDoNotShadow: no family prefix is a prefix of a
// different family's key space in a way that would misclassify it.
func TestNamedLockOrder_PrefixesDoNotShadow(t *testing.T) {
	seen := map[string]bool{}
	for i, p := range NamedLockOrder {
		require.Falsef(t, seen[p], "duplicate family %q", p)
		seen[p] = true
		r, _ := namedLockFamily(p + "1")
		if p == "last-admin-guard" {
			r, _ = namedLockFamily(p)
		}
		require.Equalf(t, i, r, "family %q resolves to rank %d", p, r)
	}
}
