// mfa_clock_trust_test.go — regression tests for "expiry check trusts a
// caller-supplied timestamp instead of the server's real clock"
// (G-wave6, findings-normalized.json uid
// findings-handlers/handlers-users-crud.json#0, plus two structurally
// identical sibling call sites found during the fix).
//
// Before the fix, GetActiveMFAChallenge / ConsumeMFAChallenge
// (users_crud.go), ConsumeWebAuthnSessionProxy (webauthn_proxy.go), and
// GetActiveMFAStepUpGrantProxy (mfa_stepup_proxy.go) all decoded a
// caller-supplied `now` field from the request body and passed it straight
// into the storage layer's "is this row still active" expiry comparison,
// instead of using the server's own clock. A caller who could reach these
// endpoints (behind users.write / system.read / system.write respectively)
// could therefore supply a `now` from before a row's real expiry to keep an
// already-expired challenge/session/grant usable past its TTL, or a
// far-future `now` to make a still-live row look expired (denial of
// service against a legitimate in-progress login/step-up).
//
// Each pair of tests below inserts a row with a REAL expiry relative to
// time.Now(), then sends a request whose `now` field — if it were still
// trusted — would flip the outcome, and asserts the server's real clock
// wins regardless.
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// setupMFAClockTrustTest builds a UserHandler and AuthHandler over an
// isolated in-memory SQLite DB, so each test can insert MFAChallenge/
// WebAuthnSession/MFAStepUpGrant rows with a precisely-controlled ExpiresAt
// without interference from the shared DB other _test.go files in this
// package reuse across the whole test binary.
func setupMFAClockTrustTest(t *testing.T) (*UserHandler, *AuthHandler, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.MFAChallenge{}, &models.WebAuthnSession{}, &models.MFAStepUpGrant{},
	))
	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	uh, err := NewUserHandler(coreService)
	require.NoError(t, err)
	ah := NewAuthHandler(coreService, false)
	return uh, ah, db
}

// --- users_crud.go: GetActiveMFAChallenge / ConsumeMFAChallenge ---

func TestUserHandler_GetActiveMFAChallenge_ExpiredStaysExpiredDespiteClientNow(t *testing.T) {
	uh, _, db := setupMFAClockTrustTest(t)
	realNow := time.Now()
	// Genuinely expired 1 hour ago by the server's real clock.
	require.NoError(t, db.Create(&models.MFAChallenge{
		UserID: 1, TokenHash: "expired-tok", ExpiresAt: realNow.Add(-1 * time.Hour), CreatedAt: realNow.Add(-2 * time.Hour),
	}).Error)

	// Attacker supplies a `now` from BEFORE the real expiry, which — if
	// trusted — would make expires_at(-1h) > now(-2h) true, i.e. the
	// challenge would wrongly look still-active.
	spoofedNow := realNow.Add(-2 * time.Hour)
	body, err := json.Marshal(map[string]any{"token_hash": "expired-tok", "now": spoofedNow})
	require.NoError(t, err)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	uh.GetActiveMFAChallenge(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code, "server must use its own clock and correctly treat the challenge as expired")
}

func TestUserHandler_ConsumeMFAChallenge_ExpiredStaysExpiredDespiteClientNow(t *testing.T) {
	uh, _, db := setupMFAClockTrustTest(t)
	realNow := time.Now()
	require.NoError(t, db.Create(&models.MFAChallenge{
		UserID: 1, TokenHash: "expired-tok2", ExpiresAt: realNow.Add(-1 * time.Hour), CreatedAt: realNow.Add(-2 * time.Hour),
	}).Error)

	spoofedNow := realNow.Add(-2 * time.Hour)
	body, err := json.Marshal(map[string]any{"token_hash": "expired-tok2", "now": spoofedNow})
	require.NoError(t, err)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	uh.ConsumeMFAChallenge(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code, "server must use its own clock and refuse to consume an expired challenge")
}

func TestUserHandler_GetActiveMFAChallenge_ActiveStaysActiveDespiteFarFutureClientNow(t *testing.T) {
	uh, _, db := setupMFAClockTrustTest(t)
	realNow := time.Now()
	// Genuinely NOT yet expired: expires 5 minutes from now.
	require.NoError(t, db.Create(&models.MFAChallenge{
		UserID: 1, TokenHash: "active-tok", ExpiresAt: realNow.Add(5 * time.Minute), CreatedAt: realNow,
	}).Error)

	// Attacker supplies a far-future `now`, which — if trusted — would make
	// expires_at(+5m) > now(+1yr) false, i.e. the still-live challenge would
	// wrongly look expired (DoS against the legitimate in-progress login).
	spoofedNow := realNow.Add(365 * 24 * time.Hour)
	body, err := json.Marshal(map[string]any{"token_hash": "active-tok", "now": spoofedNow})
	require.NoError(t, err)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	uh.GetActiveMFAChallenge(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "server must use its own clock and correctly treat the still-live challenge as active")
}

func TestUserHandler_ConsumeMFAChallenge_ActiveStaysActiveDespiteFarFutureClientNow(t *testing.T) {
	uh, _, db := setupMFAClockTrustTest(t)
	realNow := time.Now()
	require.NoError(t, db.Create(&models.MFAChallenge{
		UserID: 1, TokenHash: "active-tok2", ExpiresAt: realNow.Add(5 * time.Minute), CreatedAt: realNow,
	}).Error)

	spoofedNow := realNow.Add(365 * 24 * time.Hour)
	body, err := json.Marshal(map[string]any{"token_hash": "active-tok2", "now": spoofedNow})
	require.NoError(t, err)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)))
	w := httptest.NewRecorder()
	uh.ConsumeMFAChallenge(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "server must use its own clock and successfully consume the still-live challenge")
}

// --- webauthn_proxy.go: ConsumeWebAuthnSessionProxy (sibling bug) ---

func TestAuthHandler_ConsumeWebAuthnSessionProxy_ExpiredStaysExpiredDespiteClientNow(t *testing.T) {
	_, ah, db := setupMFAClockTrustTest(t)
	realNow := time.Now()
	require.NoError(t, db.Create(&models.WebAuthnSession{
		UserID: 1, TokenHash: "wa-expired-tok", Purpose: "login", ExpiresAt: realNow.Add(-1 * time.Hour), CreatedAt: realNow.Add(-2 * time.Hour),
	}).Error)

	spoofedNow := realNow.Add(-2 * time.Hour)
	body, err := json.Marshal(map[string]any{"token_hash": "wa-expired-tok", "now": spoofedNow})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	ah.ConsumeWebAuthnSessionProxy(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code, "server must use its own clock and refuse to consume an expired webauthn session")
}

func TestAuthHandler_ConsumeWebAuthnSessionProxy_ActiveStaysActiveDespiteFarFutureClientNow(t *testing.T) {
	_, ah, db := setupMFAClockTrustTest(t)
	realNow := time.Now()
	require.NoError(t, db.Create(&models.WebAuthnSession{
		UserID: 1, TokenHash: "wa-active-tok", Purpose: "login", ExpiresAt: realNow.Add(5 * time.Minute), CreatedAt: realNow,
	}).Error)

	spoofedNow := realNow.Add(365 * 24 * time.Hour)
	body, err := json.Marshal(map[string]any{"token_hash": "wa-active-tok", "now": spoofedNow})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	ah.ConsumeWebAuthnSessionProxy(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "server must use its own clock and successfully consume the still-live webauthn session")
}

// --- mfa_stepup_proxy.go: GetActiveMFAStepUpGrantProxy (sibling bug) ---

func TestAuthHandler_GetActiveMFAStepUpGrantProxy_ExpiredStaysExpiredDespiteClientNow(t *testing.T) {
	_, ah, db := setupMFAClockTrustTest(t)
	realNow := time.Now().UTC()
	// models.MFAStepUpGrant.BeforeSave normalizes ExpiresAt to UTC; write it
	// pre-normalized here for clarity.
	require.NoError(t, db.Create(&models.MFAStepUpGrant{
		UserID: 1, ExpiresAt: realNow.Add(-1 * time.Hour), CreatedAt: realNow.Add(-2 * time.Hour),
	}).Error)

	spoofedNow := realNow.Add(-2 * time.Hour)
	body, err := json.Marshal(map[string]any{"user_id": 1, "now": spoofedNow})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	ah.GetActiveMFAStepUpGrantProxy(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Success bool `json:"success"`
		Data    any  `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.Nil(t, resp.Data, "server must use its own clock: an expired grant must not be returned as active")
}

func TestAuthHandler_GetActiveMFAStepUpGrantProxy_ActiveStaysActiveDespiteFarFutureClientNow(t *testing.T) {
	_, ah, db := setupMFAClockTrustTest(t)
	realNow := time.Now().UTC()
	require.NoError(t, db.Create(&models.MFAStepUpGrant{
		UserID: 1, ExpiresAt: realNow.Add(5 * time.Minute), CreatedAt: realNow,
	}).Error)

	spoofedNow := realNow.Add(365 * 24 * time.Hour)
	body, err := json.Marshal(map[string]any{"user_id": 1, "now": spoofedNow})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	ah.GetActiveMFAStepUpGrantProxy(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Success bool `json:"success"`
		Data    any  `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.NotNil(t, resp.Data, "server must use its own clock: a still-live grant must be returned as active")
}
