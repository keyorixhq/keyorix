// config_s27_test.go — s27 coverage sweep for internal/storage/remote/config.go.
//
// Targets:
//
//	config.go expandEnvVars (50%)
//	  — plain string with no "${...}" (closure never invoked)
//	  — string with a set env-var placeholder (expanded to real value)
//	  — string with an unset env-var placeholder (expanded to empty string)
//	  — multiple placeholders in one string
//
//	config.go Validate (87.5%)
//	  — loopback http:// URL is allowed (explicit carve-out for local dev)
//	  — non-https, non-loopback URL is rejected with a clear "scheme" error
//	  — TimeoutSeconds<=0 defaults to 30
//	  — RetryAttempts<=0 defaults to 3
package remote

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// expandEnvVars
// ---------------------------------------------------------------------------

// TestExpandEnvVars_S27_NoPlaceholders verifies that a string without any
// "${...}" markers is returned unchanged (the os.Expand callback is never
// invoked with a real key in this path).
func TestExpandEnvVars_S27_NoPlaceholders(t *testing.T) {
	got := expandEnvVars("https://keyorix.example.com/api")
	assert.Equal(t, "https://keyorix.example.com/api", got)
}

// TestExpandEnvVars_S27_SetsEnvVarExpanded verifies that a "${VAR}" placeholder
// is replaced with the current value of that environment variable.
func TestExpandEnvVars_S27_SetsEnvVarExpanded(t *testing.T) {
	t.Setenv("_KEYORIX_S27_EXPAND_TOKEN", "tok-abc-123")
	got := expandEnvVars("Bearer ${_KEYORIX_S27_EXPAND_TOKEN}")
	assert.Equal(t, "Bearer tok-abc-123", got)
}

// TestExpandEnvVars_S27_UnsetVarExpandsToEmpty verifies that an unset variable
// expands to an empty string (os.Getenv returns ""), leaving the rest of the
// value intact.
func TestExpandEnvVars_S27_UnsetVarExpandsToEmpty(t *testing.T) {
	t.Setenv("_KEYORIX_S27_UNSET_VAR", "")
	got := expandEnvVars("prefix-${_KEYORIX_S27_UNSET_VAR}-suffix")
	assert.Equal(t, "prefix--suffix", got)
}

// TestExpandEnvVars_S27_MultiplePlaceholders verifies that several distinct
// placeholders in one string are each individually expanded.
func TestExpandEnvVars_S27_MultiplePlaceholders(t *testing.T) {
	t.Setenv("_KEYORIX_S27_HOST", "my-host")
	t.Setenv("_KEYORIX_S27_PORT", "8443")
	got := expandEnvVars("https://${_KEYORIX_S27_HOST}:${_KEYORIX_S27_PORT}/api")
	assert.Equal(t, "https://my-host:8443/api", got)
}

// ---------------------------------------------------------------------------
// Config.Validate — additional branches
// ---------------------------------------------------------------------------

// TestValidate_S27_LoopbackHTTPAllowed verifies that http:// is accepted when
// the host resolves to a loopback address (local dev carve-out).
func TestValidate_S27_LoopbackHTTPAllowed(t *testing.T) {
	c := &Config{
		BaseURL: "http://localhost:8080",
		APIKey:  "dev-key",
	}
	require.NoError(t, c.Validate(), "http://localhost must be allowed for local dev")
}

// TestValidate_S27_LoopbackIPHTTPAllowed verifies that http://127.0.0.1 is also
// accepted as a loopback host.
func TestValidate_S27_LoopbackIPHTTPAllowed(t *testing.T) {
	c := &Config{
		BaseURL: "http://127.0.0.1:9090",
		APIKey:  "dev-key",
	}
	require.NoError(t, c.Validate())
}

// TestValidate_S27_NonHTTPSNonLoopbackRejected verifies that a non-loopback
// http:// URL is rejected with a message mentioning "https".
func TestValidate_S27_NonHTTPSNonLoopbackRejected(t *testing.T) {
	c := &Config{
		BaseURL: "http://remote-server.example.com",
		APIKey:  "some-key",
	}
	err := c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

// TestValidate_S27_DefaultsTimeoutAndRetry verifies that TimeoutSeconds<=0 is
// defaulted to 30 and RetryAttempts<=0 is defaulted to 3 after Validate().
func TestValidate_S27_DefaultsTimeoutAndRetry(t *testing.T) {
	c := &Config{
		BaseURL:        "https://api.example.com",
		APIKey:         "my-key",
		TimeoutSeconds: 0,  // <=0 → default 30
		RetryAttempts:  -1, // <=0 → default 3
	}
	require.NoError(t, c.Validate())
	assert.Equal(t, 30, c.TimeoutSeconds)
	assert.Equal(t, 3, c.RetryAttempts)
}

// TestValidate_S27_ExplicitTimeoutAndRetryPreserved verifies that explicit
// positive values are NOT overwritten by the defaults.
func TestValidate_S27_ExplicitTimeoutAndRetryPreserved(t *testing.T) {
	c := &Config{
		BaseURL:        "https://api.example.com",
		APIKey:         "my-key",
		TimeoutSeconds: 60,
		RetryAttempts:  5,
	}
	require.NoError(t, c.Validate())
	assert.Equal(t, 60, c.TimeoutSeconds)
	assert.Equal(t, 5, c.RetryAttempts)
}
