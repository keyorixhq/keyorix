package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// postInitSystemBody posts body to POST /system/init on a fresh server whose
// bootstrap token is serverToken, sending header (if any) as the caller's token.
func postInitSystemBody(t *testing.T, serverToken, header, body string) (int, map[string]any) {
	t.Helper()
	c := freshCoreS7(t)
	c.SetBootstrapToken(serverToken)
	h := NewAuthHandler(c, false)

	req := httptest.NewRequest(http.MethodPost, "/system/init", strings.NewReader(body))
	if header != "" {
		req.Header.Set("X-Keyorix-Bootstrap-Token", header)
	}
	w := httptest.NewRecorder()
	h.InitSystem(w, req)

	var out map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	return w.Code, out
}

// A caller who holds the bootstrap token but sends details the server rejects
// (here an email with no top-level domain, the old CLI default) gets a 400 with a
// typed code that names the field, not the 403 "ask a project admin" refusal.
func TestInitSystem_InvalidEmailIs400NamingTheField(t *testing.T) {
	code, out := postInitSystemBody(t, "correct-token", "correct-token",
		`{"username":"admin","email":"admin@localhost","password":"Tr0ub4dor-and-Zebra-9!"}`)

	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "ValidationError", out["error"], "typed code, not the generic 403 \"Error\"")
	msg, _ := out["message"].(string)
	assert.Contains(t, strings.ToLower(msg), "email", "the message names the rejected field")
	details, _ := out["details"].(map[string]any)
	assert.Equal(t, "email", details["field"], "the typed detail names the rejected field")
}

// A bad username is the same class of refusal and names its own field.
func TestInitSystem_InvalidUsernameIs400NamingTheField(t *testing.T) {
	code, out := postInitSystemBody(t, "correct-token", "correct-token",
		`{"username":"a","email":"admin@example.com","password":"Tr0ub4dor-and-Zebra-9!"}`)

	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "ValidationError", out["error"])
	details, _ := out["details"].(map[string]any)
	assert.Equal(t, "username", details["field"])
}

// The token is checked before the details: without it a malformed email still
// answers the 403 token refusal and reveals nothing about validation.
func TestInitSystem_InvalidEmailWithWrongTokenStays403(t *testing.T) {
	code, out := postInitSystemBody(t, "correct-token", "not-the-token",
		`{"username":"admin","email":"admin@localhost","password":"Tr0ub4dor-and-Zebra-9!"}`)

	assert.Equal(t, http.StatusForbidden, code)
	assert.NotEqual(t, "ValidationError", out["error"])
	assert.NotContains(t, strings.ToLower(out["message"].(string)), "email")
}

// With no server token configured, API bootstrap is disabled: still a 403.
func TestInitSystem_InvalidEmailWithNoServerTokenStays403(t *testing.T) {
	code, out := postInitSystemBody(t, "", "whatever",
		`{"username":"admin","email":"admin@localhost","password":"Tr0ub4dor-and-Zebra-9!"}`)

	assert.Equal(t, http.StatusForbidden, code)
	assert.NotEqual(t, "ValidationError", out["error"])
}
