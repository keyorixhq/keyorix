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
