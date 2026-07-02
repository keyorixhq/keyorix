package connect

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRefHasDotSegment(t *testing.T) {
	cases := []struct {
		ref  string
		want bool
	}{
		{"secret/data/myapp/config", false},
		{"secret/data/myapp/", false},
		{"prod/eu/db", false},
		{"keyorix/prod-db", false}, // AWS Secrets Manager friendly name, no dot segment
		{"projects/123/secrets/foo/versions/latest", false},
		{"", false},
		{".", true},
		{"..", true},
		{"secret/data/myapp/../otherapp/secret", true}, // exact #326 exploit trace
		{"secret/data/team-a/../../../sys/policies/acl", true},
		{"../etc/passwd", true},
		{"secret/./data", true},
	}
	for _, tc := range cases {
		assert.Equalf(t, tc.want, RefHasDotSegment(tc.ref), "RefHasDotSegment(%q)", tc.ref)
	}
}

func TestPrefixAllowed(t *testing.T) {
	t.Run("empty allowlist permits everything for a non-traversal ref", func(t *testing.T) {
		assert.True(t, prefixAllowed(nil, "anything"))
	})
	t.Run("empty allowlist still rejects a traversal-shaped ref", func(t *testing.T) {
		assert.False(t, prefixAllowed(nil, "secret/data/myapp/../otherapp/secret"))
	})
	t.Run("legitimate ref within the granted prefix is allowed", func(t *testing.T) {
		assert.True(t, prefixAllowed([]string{"secret/data/myapp/"}, "secret/data/myapp/config"))
	})
	t.Run("ref outside the granted prefix is denied", func(t *testing.T) {
		assert.False(t, prefixAllowed([]string{"secret/data/myapp/"}, "secret/data/otherapp/secret"))
	})
	t.Run("#326: traversal ref that satisfies the literal HasPrefix check is still denied", func(t *testing.T) {
		// "secret/data/myapp/../otherapp/secret" literally starts with the allowed
		// prefix "secret/data/myapp/" — a raw strings.HasPrefix check alone would
		// have permitted it, even though it resolves outside the grant.
		assert.False(t, prefixAllowed([]string{"secret/data/myapp/"}, "secret/data/myapp/../otherapp/secret"))
	})
}

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
