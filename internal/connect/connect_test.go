package connect

import "testing"

// TestPrefixAllowed_SegmentBoundary pins that an allowed_refs prefix (ADR-043) is
// matched on a path-segment boundary, not as a bare substring: a prefix "db/prod"
// authorizes "db/prod" itself and anything under it ("db/prod/user"), but must NOT
// also authorize an unrelated sibling that merely starts with the same characters,
// e.g. "db/production-other-team". A plain strings.HasPrefix would incorrectly
// over-grant that sibling.
func TestPrefixAllowed_SegmentBoundary(t *testing.T) {
	allowed := []string{"db/prod"}

	cases := []struct {
		ref  string
		want bool
	}{
		{"db/prod", true},                   // exact match
		{"db/prod/user", true},              // proper sub-path
		{"db/production-other-team", false}, // FIX: sibling namespace must NOT match
		{"db/prodX", false},                 // FIX: no segment boundary, must NOT match
		{"other/prod", false},               // unrelated ref
	}
	for _, tc := range cases {
		if got := prefixAllowed(allowed, tc.ref); got != tc.want {
			t.Errorf("prefixAllowed(%q, %q) = %v, want %v", allowed, tc.ref, got, tc.want)
		}
	}
}

// TestPrefixAllowed_TrailingSlashPrefixUnaffected proves a prefix already scoped
// with a trailing slash (the recommended, unambiguous form) continues to work
// exactly as before: it authorizes everything under it and nothing else.
func TestPrefixAllowed_TrailingSlashPrefixUnaffected(t *testing.T) {
	allowed := []string{"secret/keyorix/"}

	if !prefixAllowed(allowed, "secret/keyorix/db") {
		t.Error("expected ref under the trailing-slash prefix to be allowed")
	}
	if prefixAllowed(allowed, "secret/keyorix-other/db") {
		t.Error("expected sibling namespace to be denied")
	}
}

// TestPrefixAllowed_EmptyAllowlistUnrestricted preserves the documented behavior
// that an empty allowlist places no restriction.
func TestPrefixAllowed_EmptyAllowlistUnrestricted(t *testing.T) {
	if !prefixAllowed(nil, "anything") {
		t.Error("expected an empty allowlist to permit everything")
	}
}
