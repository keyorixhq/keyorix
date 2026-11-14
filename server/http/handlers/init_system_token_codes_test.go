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

func postInitSystem(t *testing.T, serverToken, header string) (int, map[string]any) {
	t.Helper()
	c := freshCoreS7(t)
	c.SetBootstrapToken(serverToken)
	h := NewAuthHandler(c, false)

	body := `{"username":"admin","email":"admin@example.com","password":"Admin1234!xyz"}`
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

// A wrong or missing token on a server that has one answers a typed 403.
func TestInitSystem_WrongOrMissingTokenHasTypedCode(t *testing.T) {
	for name, header := range map[string]string{"wrong": "not-the-token", "missing": ""} {
		t.Run(name, func(t *testing.T) {
			code, out := postInitSystem(t, "correct-token", header)
			assert.Equal(t, http.StatusForbidden, code)
			assert.Equal(t, "InvalidBootstrapToken", out["error"])
		})
	}
}

// With no server token, API init is disabled: its own typed code and the hint.
func TestInitSystem_ServerTokenUnsetHasTypedCodeAndHint(t *testing.T) {
	code, out := postInitSystem(t, "", "whatever")
	assert.Equal(t, http.StatusForbidden, code)
	assert.Equal(t, "BootstrapAPIDisabled", out["error"])
	msg, _ := out["message"].(string)
	assert.Contains(t, msg, "KEYORIX_BOOTSTRAP_TOKEN")
	assert.Contains(t, msg, "keyorix system init")
}
