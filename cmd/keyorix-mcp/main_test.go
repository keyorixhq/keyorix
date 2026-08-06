package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// KEYORIX_MCP_MAX_READS unset must apply defaultMaxReads (a bounded, non-infinite
// ceiling) rather than "unlimited" — see the defaultMaxReads comment for rationale.
func TestResolveMaxReads_UnsetAppliesDefault(t *testing.T) {
	n, usedDefault, err := resolveMaxReads("")
	require.NoError(t, err)
	assert.True(t, usedDefault)
	assert.Equal(t, defaultMaxReads, n)
}

func TestResolveMaxReads_ValidOverride(t *testing.T) {
	n, usedDefault, err := resolveMaxReads("500")
	require.NoError(t, err)
	assert.False(t, usedDefault)
	assert.Equal(t, 500, n)
}

func TestResolveMaxReads_InvalidIsFatal(t *testing.T) {
	for _, raw := range []string{"not-a-number", "0", "-5", "3.5"} {
		_, _, err := resolveMaxReads(raw)
		assert.Error(t, err, "raw=%q must be rejected, not silently fall back to unlimited", raw)
	}
}

// An unset KEYORIX_MCP_ALLOWED_REFS means "not configured" — no restriction, no error.
func TestResolveAllowedRefs_UnsetIsNoRestriction(t *testing.T) {
	patterns, err := resolveAllowedRefs("")
	require.NoError(t, err)
	assert.Nil(t, patterns)
}

func TestResolveAllowedRefs_ValidPatterns(t *testing.T) {
	patterns, err := resolveAllowedRefs("app/production/*, app/staging/db-*")
	require.NoError(t, err)
	assert.Equal(t, []string{"app/production/*", "app/staging/db-*"}, patterns)
}

// A set-but-empty-after-parsing value (e.g. a stray trailing comma from templating an
// empty list) must be a fatal misconfiguration, not a silent fail-open to "no
// restriction" — see the resolveAllowedRefs comment for why (#122 finding).
func TestResolveAllowedRefs_ZeroPatternsIsFatal(t *testing.T) {
	for _, raw := range []string{",", ",,", "   ", " , "} {
		patterns, err := resolveAllowedRefs(raw)
		assert.Error(t, err, "raw=%q must be rejected, not silently allow everything", raw)
		assert.Nil(t, patterns)
	}
}
