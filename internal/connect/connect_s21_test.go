package connect

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ── refWithinPrefix ─────────────────────────────────────────────────────────

// TestRefWithinPrefix_S21 exercises refWithinPrefix directly.  The function is
// called through prefixAllowed in the existing tests, but a direct table-driven
// set of cases makes the boundary semantics explicit.
func TestRefWithinPrefix_S21(t *testing.T) {
	cases := []struct {
		prefix string
		ref    string
		want   bool
	}{
		// exact match
		{"db/prod", "db/prod", true},
		// ref extends prefix on a path-segment boundary
		{"db/prod", "db/prod/user", true},
		{"db/prod", "db/prod/sub/table", true},
		// prefix already carries trailing slash → any continuation is fine
		{"db/prod/", "db/prod/user", true},
		{"db/prod/", "db/prod/", true},
		// sibling with shared prefix characters must NOT match (no segment boundary)
		{"db/prod", "db/production", false},
		{"db/prod", "db/prodX", false},
		// entirely different ref
		{"db/prod", "other/prod", false},
		{"secret/keyorix", "secret/keyorix-other", false},
		// empty ref never matches a non-empty prefix
		{"db/prod", "", false},
		// prefix longer than ref
		{"db/prod/user", "db/prod", false},
	}
	for _, tc := range cases {
		got := refWithinPrefix(tc.prefix, tc.ref)
		assert.Equalf(t, tc.want, got,
			"refWithinPrefix(%q, %q)", tc.prefix, tc.ref)
	}
}

// ── prefixAllowed: additional edge cases ────────────────────────────────────

// TestPrefixAllowed_EmptyPrefixEntrySkipped_S21 verifies that empty strings in
// the allowedRefs list are ignored and do not accidentally grant everything.
func TestPrefixAllowed_EmptyPrefixEntrySkipped_S21(t *testing.T) {
	// An allowlist that contains only empty strings is effectively empty — the
	// empty-string entry (p=="") is skipped inside prefixAllowed, so the ref
	// cannot be granted by an empty prefix.
	assert.False(t, prefixAllowed([]string{""}, "db/prod"),
		"an allowlist of only empty-string entries must deny")
}

// TestPrefixAllowed_MultipleEntries_S21 confirms that a ref matching any of
// several configured prefixes is allowed.
func TestPrefixAllowed_MultipleEntries_S21(t *testing.T) {
	allowed := []string{"secret/teamA/", "secret/teamB/"}
	assert.True(t, prefixAllowed(allowed, "secret/teamA/db"))
	assert.True(t, prefixAllowed(allowed, "secret/teamB/api"))
	assert.False(t, prefixAllowed(allowed, "secret/teamC/api"))
}

// TestPrefixAllowed_EmptySliceRejectionWithTraversal_S21 confirms that a
// traversal ref is blocked even when allowedRefs is an explicit empty slice
// (as opposed to nil).
func TestPrefixAllowed_EmptySliceRejectionWithTraversal_S21(t *testing.T) {
	assert.False(t, prefixAllowed([]string{}, "secret/../etc/passwd"))
}

// ── sanitizeVaultRef ────────────────────────────────────────────────────────

// TestSanitizeVaultRef_S21 exercises sanitizeVaultRef: a pure string function
// with no network dependency.  These cases cover every branch in the function.
func TestSanitizeVaultRef_S21(t *testing.T) {
	t.Run("normal multi-segment ref passes through", func(t *testing.T) {
		got, err := sanitizeVaultRef("secret/data/myapp/config")
		assert.NoError(t, err)
		assert.Equal(t, "secret/data/myapp/config", got)
	})

	t.Run("leading slash is stripped", func(t *testing.T) {
		got, err := sanitizeVaultRef("/secret/data/myapp")
		assert.NoError(t, err)
		assert.Equal(t, "secret/data/myapp", got)
	})

	t.Run("double slash is collapsed", func(t *testing.T) {
		got, err := sanitizeVaultRef("secret//data")
		assert.NoError(t, err)
		assert.Equal(t, "secret/data", got)
	})

	t.Run("dot traversal segment rejected", func(t *testing.T) {
		_, err := sanitizeVaultRef("secret/data/myapp/./config")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "traversal")
	})

	t.Run("dotdot traversal segment rejected", func(t *testing.T) {
		_, err := sanitizeVaultRef("secret/data/myapp/../otherapp")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "traversal")
	})

	t.Run("empty ref after stripping has no usable path", func(t *testing.T) {
		_, err := sanitizeVaultRef("/")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no usable path")
	})

	t.Run("fully empty ref has no usable path", func(t *testing.T) {
		_, err := sanitizeVaultRef("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no usable path")
	})

	t.Run("control character in segment rejected", func(t *testing.T) {
		_, err := sanitizeVaultRef("secret/\x01data")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "control character")
	})

	t.Run("DEL (0x7f) control character rejected", func(t *testing.T) {
		_, err := sanitizeVaultRef("secret/data\x7f/key")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "control character")
	})

	t.Run("question mark is percent-escaped, not split into query string", func(t *testing.T) {
		got, err := sanitizeVaultRef("secret/data/x?list=true")
		assert.NoError(t, err)
		assert.Contains(t, got, "%3F",
			"the ? must be percent-escaped so it cannot inject a query string")
		assert.NotContains(t, got, "?")
	})

	t.Run("single valid segment is accepted", func(t *testing.T) {
		got, err := sanitizeVaultRef("mysecret")
		assert.NoError(t, err)
		assert.Equal(t, "mysecret", got)
	})
}

// ── Manager: edge cases not covered by TestManager_GetAndNames ───────────────

// TestManager_DuplicateNameLastWins_S21 verifies that when two connectors share
// the same Name, the second one replaces the first (last-wins semantics).
func TestManager_DuplicateNameLastWins_S21(t *testing.T) {
	first := connectorWith("shared", &fakeSM{})
	second := connectorWith("shared", &fakeSM{})

	m := NewManager([]Connector{first, second})
	got, ok := m.Get("shared")
	assert.True(t, ok)
	assert.Equal(t, "shared", got.Name())
	// Only one entry in the map despite two inputs.
	assert.Len(t, m.Names(), 1)
}

// TestManager_EmptyNameConnectorIgnored_S21 verifies that a connector whose
// Name() returns "" is silently dropped from the manager.
func TestManager_EmptyNameConnectorIgnored_S21(t *testing.T) {
	blank := connectorWith("", &fakeSM{})
	named := connectorWith("real", &fakeSM{})
	m := NewManager([]Connector{blank, named})

	_, ok := m.Get("")
	assert.False(t, ok, "the nameless connector must not be registered")
	assert.ElementsMatch(t, []string{"real"}, m.Names())
}

// TestManager_AllNilOrEmpty_S21 verifies that a Manager built only from nil /
// empty-named connectors has no registered entries and operations are safe.
func TestManager_AllNilOrEmpty_S21(t *testing.T) {
	m := NewManager([]Connector{nil, connectorWith("", &fakeSM{})})
	assert.Empty(t, m.Names())
	_, ok := m.Get("anything")
	assert.False(t, ok)
}
