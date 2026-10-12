package storage

import (
	"strings"
	"testing"
)

func TestCheckNamedLockOrder(t *testing.T) {
	cases := []struct {
		name    string
		held    []string
		next    string
		wantErr string // "" = allowed
	}{
		{"first acquisition", nil, "last-admin-guard", ""},
		{"declared order", []string{"last-admin-guard"}, "project-admin-guard:3", ""},
		{"skip a rank", []string{"dual-control-approval:request:9"}, "sod-grant:user:1", ""},
		{"nestable ascending", []string{"last-admin-guard", "project-admin-guard:7"}, "project-admin-guard:8", ""},
		{"re-entrant same key", []string{"sod-grant:user:4"}, "sod-grant:user:4", ""},
		{"multi-part id", []string{"project-membership:2:5"}, "sod-grant:user:5", ""},
		{"inversion", []string{"project-admin-guard:3"}, "last-admin-guard", "requires the reverse"},
		{"inversion deeper in stack", []string{"project-membership:1:1", "sod-grant:user:2"}, "project-admin-guard:1", "requires the reverse"},
		{"nestable descending", []string{"project-admin-guard:8"}, "project-admin-guard:7", "ascending ID order"},
		{"non-nestable self", []string{"sod-grant:machine:1"}, "sod-grant:machine:2", "not declared Nestable"},
		{"unknown family", nil, "some-new-lock:1", "matches no family"},
		{"non-numeric id", nil, "project-admin-guard:abc", "matches no family"},
		{"exact family with suffix", nil, "last-admin-guard:1", "matches no family"},
	}
	for _, tc := range cases {
		err := CheckNamedLockOrder(tc.held, tc.next)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: want allowed, got %v", tc.name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: want error containing %q, got %v", tc.name, tc.wantErr, err)
		}
	}
}

// TestNamedLockOrder_PrefixesAreUnambiguous: a key must match exactly one
// family, or the rank it gets depends on table order rather than on the
// declaration.
func TestNamedLockOrder_PrefixesAreUnambiguous(t *testing.T) {
	for i, a := range NamedLockOrder {
		for j, b := range NamedLockOrder {
			if i != j && !a.Exact && strings.HasPrefix(b.Prefix, a.Prefix) {
				t.Errorf("family %q is a prefix of family %q", a.Prefix, b.Prefix)
			}
		}
	}
}
