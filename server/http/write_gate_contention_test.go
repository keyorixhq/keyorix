package http

// write_gate_contention_test.go — RESIL-1 (#2637 follow-up): when the SQLite
// write gate is saturated, a write must surface as 503 + Retry-After with a
// fixed body, not as a 500 carrying internal detail.
//
// Unlike newTestCore (ungated in-memory SQLite), these tests open the store
// through storage.NewStorageFactory so the real write gate is in the path, then
// saturate it by holding one write transaction open and shortening the gate's
// wait bound.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newGatedCore builds a core on a file-backed SQLite store opened through the
// production factory (so the write gate is installed), and returns the core and
// the gated *gorm.DB.
func newGatedCore(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	cfg := &config.Config{Storage: config.StorageConfig{
		Type:     "local",
		Database: config.DatabaseConfig{Path: filepath.Join(t.TempDir(), "gate.db")},
	}}
	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	ls, ok := st.(*store.LocalStorage)
	require.True(t, ok, "factory must return *store.LocalStorage for type local, got %T", st)
	t.Cleanup(func() {
		if sqlDB, derr := ls.DB().DB(); derr == nil {
			_ = sqlDB.Close()
		}
	})
	return core.NewKeyorixCore(st), ls.DB()
}

// saturateWriteGate holds the gate with an open write transaction and shortens
// the wait bound; the returned func releases both.
func saturateWriteGate(t *testing.T, db *gorm.DB) {
	t.Helper()
	restore := storage.SetWriteGateMaxWaitForTest(150 * time.Millisecond)
	holder := db.Begin()
	require.NoError(t, holder.Error)
	t.Cleanup(func() {
		_ = holder.Rollback()
		restore()
	})
}

func TestHTTPWriteGateContention_Returns503WithRetryAfter(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c, db := newGatedCore(t)
	router, err := NewRouter(&config.Config{
		Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}},
	}, c)
	require.NoError(t, err)
	token := createTestToken(t, c)

	saturateWriteGate(t, db)

	body, _ := json.Marshal(map[string]string{"name": "contended-group"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/groups", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	t.Logf("status=%d retry-after=%q body=%s", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, "gate contention must be a 503, not a generic 500")
	ra, convErr := strconv.Atoi(rec.Header().Get("Retry-After"))
	require.NoError(t, convErr, "Retry-After must be integer seconds")
	require.Positive(t, ra)

	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Equal(t, "ServiceUnavailable", out["error"])
	require.EqualValues(t, http.StatusServiceUnavailable, out["code"])
	lower := strings.ToLower(rec.Body.String())
	for _, leak := range []string{"sqlite", "write lock", "gorm", "database", "contention"} {
		require.NotContains(t, lower, leak, "body must carry no internal detail")
	}
}

// loginResult is what a client can observe of a login attempt.
type loginResult struct {
	status  int
	body    string
	headers http.Header
}

func postLogin(router http.Handler, username, password string) loginResult {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return loginResult{status: rec.Code, body: rec.Body.String(), headers: rec.Header()}
}

// TestLoginWriteGateContention_LooksLikeWrongCredential proves the credential
// surface is unchanged externally (#2740 option C / #2888): the password matched
// on an MFA account, then the write that creates the MFA challenge hit the
// saturated gate. The client must see byte-for-byte what a wrong password gets —
// not a 500, not the 503 the rest of the API uses, no Retry-After.
func TestLoginWriteGateContention_LooksLikeWrongCredential(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c, db := newGatedCore(t)
	router, err := NewRouter(&config.Config{
		Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}},
	}, c)
	require.NoError(t, err)
	_ = createTestToken(t, c) // bootstraps "testadmin" / "TestPassword123!"
	require.NoError(t, db.Exec("UPDATE users SET mfa_enabled = ? WHERE username = ?", true, "testadmin").Error)

	saturateWriteGate(t, db)

	wrong := postLogin(router, "testadmin", "definitely-wrong-password")
	right := postLogin(router, "testadmin", "TestPassword123!")

	t.Logf("wrong: %d %s", wrong.status, wrong.body)
	t.Logf("right: %d %s", right.status, right.body)
	require.Equal(t, http.StatusUnauthorized, wrong.status, "baseline: a wrong password is a 401")
	require.Equal(t, wrong.status, right.status, "a matched credential that hit the gate must not change the status")
	require.Equal(t, wrong.body, right.body, "body must be byte-identical to the wrong-credential body")
	for _, h := range []string{"Content-Type", "Retry-After", "Set-Cookie", "WWW-Authenticate"} {
		require.Equal(t, wrong.headers.Values(h), right.headers.Values(h), "header %s must be identical", h)
	}
}
