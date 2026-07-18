// config_s24_test.go — coverage sweep for s24 gaps in internal/storage/remote.
//
// Targets:
//
//	config.go GetAPIKeyFromEnv (28.6%)
//	  — direct literal API key (no "${") returns it unchanged
//	  — empty APIKey → check KEYORIX_API_KEY env var
//	  — "${VAR_NAME}" placeholder → check KEYORIX_API_KEY env var
//	  — no env var set → falls back through all candidates and returns original APIKey
//
//	client.go IsNotFound (0.0%)
//	  — HTTPError with StatusCode 404 → true
//	  — HTTPError with non-404 status → false
package remote

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// GetAPIKeyFromEnv
// ---------------------------------------------------------------------------

// TestGetAPIKeyFromEnv_S24_LiteralKey verifies that when APIKey is a plain
// string (no "${" prefix), GetAPIKeyFromEnv returns it unchanged without
// consulting environment variables.
func TestGetAPIKeyFromEnv_S24_LiteralKey(t *testing.T) {
	c := &Config{APIKey: "my-literal-api-key"}
	got := c.GetAPIKeyFromEnv()
	assert.Equal(t, "my-literal-api-key", got)
}

// TestGetAPIKeyFromEnv_S24_EnvVarFallbackKEYORIX_API_KEY verifies that when
// APIKey is empty, GetAPIKeyFromEnv returns the value from KEYORIX_API_KEY.
func TestGetAPIKeyFromEnv_S24_EnvVarFallbackKEYORIX_API_KEY(t *testing.T) {
	t.Setenv("KEYORIX_API_KEY", "from-env-keyorix-api-key")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("API_KEY", "")

	c := &Config{APIKey: ""}
	got := c.GetAPIKeyFromEnv()
	assert.Equal(t, "from-env-keyorix-api-key", got)
}

// TestGetAPIKeyFromEnv_S24_EnvVarFallbackKEYORIX_TOKEN verifies that when
// APIKey is empty and KEYORIX_API_KEY is unset, GetAPIKeyFromEnv falls back to
// KEYORIX_TOKEN.
func TestGetAPIKeyFromEnv_S24_EnvVarFallbackKEYORIX_TOKEN(t *testing.T) {
	t.Setenv("KEYORIX_API_KEY", "")
	t.Setenv("KEYORIX_TOKEN", "from-env-keyorix-token")
	t.Setenv("API_KEY", "")

	c := &Config{APIKey: ""}
	got := c.GetAPIKeyFromEnv()
	assert.Equal(t, "from-env-keyorix-token", got)
}

// TestGetAPIKeyFromEnv_S24_EnvVarFallbackAPI_KEY verifies that when APIKey is
// empty and both KEYORIX_API_KEY and KEYORIX_TOKEN are unset, GetAPIKeyFromEnv
// falls back to API_KEY.
func TestGetAPIKeyFromEnv_S24_EnvVarFallbackAPI_KEY(t *testing.T) {
	t.Setenv("KEYORIX_API_KEY", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("API_KEY", "from-env-api-key")

	c := &Config{APIKey: ""}
	got := c.GetAPIKeyFromEnv()
	assert.Equal(t, "from-env-api-key", got)
}

// TestGetAPIKeyFromEnv_S24_NoEnvVarsReturnsOriginal verifies that when APIKey
// is empty and no environment variables are set, GetAPIKeyFromEnv returns the
// original (empty) APIKey value.
func TestGetAPIKeyFromEnv_S24_NoEnvVarsReturnsOriginal(t *testing.T) {
	t.Setenv("KEYORIX_API_KEY", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("API_KEY", "")

	c := &Config{APIKey: ""}
	got := c.GetAPIKeyFromEnv()
	assert.Equal(t, "", got)
}

// TestGetAPIKeyFromEnv_S24_PlaceholderChecksEnv verifies that when APIKey looks
// like an unresolved env-var placeholder ("${KEYORIX_API_KEY}"), the function
// does NOT return it verbatim but instead falls back to the actual environment.
func TestGetAPIKeyFromEnv_S24_PlaceholderChecksEnv(t *testing.T) {
	t.Setenv("KEYORIX_API_KEY", "resolved-from-env")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("API_KEY", "")

	c := &Config{APIKey: "${KEYORIX_API_KEY}"}
	got := c.GetAPIKeyFromEnv()
	assert.Equal(t, "resolved-from-env", got)
}

// TestGetAPIKeyFromEnv_S24_PlaceholderNoEnvReturnsPlaceholder verifies that
// when APIKey is a "${VAR}" placeholder and no environment variable is set,
// the original placeholder string is returned.
func TestGetAPIKeyFromEnv_S24_PlaceholderNoEnvReturnsPlaceholder(t *testing.T) {
	t.Setenv("KEYORIX_API_KEY", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("API_KEY", "")

	c := &Config{APIKey: "${SOME_UNSET_VAR}"}
	got := c.GetAPIKeyFromEnv()
	// No env var matches → returns the original placeholder
	assert.Equal(t, "${SOME_UNSET_VAR}", got)
}

// ---------------------------------------------------------------------------
// IsNotFound
// ---------------------------------------------------------------------------

// TestHTTPError_IsNotFound_S24_True verifies that IsNotFound returns true when
// the HTTP status code is 404 Not Found.
func TestHTTPError_IsNotFound_S24_True(t *testing.T) {
	e := &HTTPError{StatusCode: http.StatusNotFound, Status: "Not Found"}
	assert.True(t, e.IsNotFound(), "IsNotFound must return true for 404")
}

// TestHTTPError_IsNotFound_S24_False_400 verifies that IsNotFound returns false
// for a 400 Bad Request error.
func TestHTTPError_IsNotFound_S24_False_400(t *testing.T) {
	e := &HTTPError{StatusCode: http.StatusBadRequest, Status: "Bad Request"}
	assert.False(t, e.IsNotFound(), "IsNotFound must return false for 400")
}

// TestHTTPError_IsNotFound_S24_False_500 verifies that IsNotFound returns false
// for a 500 Internal Server Error.
func TestHTTPError_IsNotFound_S24_False_500(t *testing.T) {
	e := &HTTPError{StatusCode: http.StatusInternalServerError, Status: "Internal Server Error"}
	assert.False(t, e.IsNotFound(), "IsNotFound must return false for 500")
}

// TestHTTPError_IsNotFound_S24_False_401 verifies that IsNotFound returns false
// for a 401 Unauthorized error.
func TestHTTPError_IsNotFound_S24_False_401(t *testing.T) {
	e := &HTTPError{StatusCode: http.StatusUnauthorized, Status: "Unauthorized"}
	assert.False(t, e.IsNotFound(), "IsNotFound must return false for 401")
}

// TestHTTPError_IsNotFound_S24_False_403 verifies that IsNotFound returns false
// for a 403 Forbidden error.
func TestHTTPError_IsNotFound_S24_False_403(t *testing.T) {
	e := &HTTPError{StatusCode: http.StatusForbidden, Status: "Forbidden"}
	assert.False(t, e.IsNotFound(), "IsNotFound must return false for 403")
}
