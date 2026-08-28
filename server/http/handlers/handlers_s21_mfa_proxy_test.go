// handlers_s21_mfa_proxy_test.go — coverage sweep targeting the storage-error
// (500) branches in mfa_management_proxy.go that remain uncovered:
//   - GetMFASecretProxy: non-not-found storage error → 500
//   - CountUnusedMFARecoveryCodesProxy: storage error → 500
//
// ActivateMFASecretProxy/DeleteMFAForUserProxy/SetUserMFAEnabledProxy/
// CreateMFARecoveryCodesProxy/DeleteMFARecoveryCodesProxy and their tests were
// DELETED (#1593, docs/adr-089-mfa-purge-relay-deletion.md) — no live caller.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freshClosedCoreS21 opens a DB via freshCoreS12WithAdmin, closes the
// underlying *sql.DB to force storage errors, and returns the handler backed by
// that broken core.
func freshClosedCoreS21(t *testing.T) *AuthHandler {
	t.Helper()
	cs, db := freshCoreS12WithAdmin(t)
	// G80: UpsertMFASecretProxy now checks AuthEncryptionActive() before ever
	// reaching storage -- wire an encryptor first so tests exercising a genuine
	// storage-layer failure (the DB close below) still reach the storage call
	// they mean to test, instead of getting intercepted earlier by the new check.
	setTestAuthEncryptor(t, cs)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	return NewAuthHandler(cs, false)
}

// ── GetMFASecretProxy ─────────────────────────────────────────────────────────

// TestGetMFASecretProxy_StorageError_S21 — valid user_id but DB is closed
// → non-not-found storage error → 500.
func TestGetMFASecretProxy_StorageError_S21(t *testing.T) {
	h := freshClosedCoreS21(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/mfa/secrets?user_id=1", nil)
	w := httptest.NewRecorder()
	h.GetMFASecretProxy(w, r)
	// closed DB returns a non-not-found error → 500.
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── CountUnusedMFARecoveryCodesProxy ─────────────────────────────────────────

// TestCountUnusedMFARecoveryCodesProxy_StorageError_S21 — valid user_id, DB
// closed → storage error → 500.
func TestCountUnusedMFARecoveryCodesProxy_StorageError_S21(t *testing.T) {
	h := freshClosedCoreS21(t)
	r := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/mfa/recovery-codes/count?user_id=1", nil)
	w := httptest.NewRecorder()
	h.CountUnusedMFARecoveryCodesProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── GetMFASecretProxy: not-found branch via context deadline ─────────────────

// TestGetMFASecretProxy_NotFoundAfterUpsert_S21 — persist a secret directly via
// storage (UpsertMFASecretProxy was deleted -- G80 liveness sweep found no live
// caller; see docs/g80-remediation-notes.md) then GET it to exercise the 200
// success branch in one shot (verifies the happy path runs through the
// not-found guard cleanly when the row exists).
func TestGetMFASecretProxy_NotFoundAfterUpsert_S21(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	setTestAuthEncryptor(t, cs)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "s21user2", Email: "s21user2@example.com", AccountState: "active"}).Error)
	// Seed a row directly via storage so GET finds it.
	require.NoError(t, cs.Storage().UpsertMFASecret(context.Background(), &models.MFASecret{
		UserID:    2,
		SecretEnc: []byte("s21enc"),
	}))

	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/mfa/secrets?user_id=2", nil)
	w := httptest.NewRecorder()
	h.GetMFASecretProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── parseMFAUserIDQuery: invalid integer branch ───────────────────────────────

// TestGetMFASecretProxy_InvalidUserIDQuery_S21 — user_id is non-empty but
// non-integer → 400 (hits the ParseUint error branch in parseMFAUserIDQuery).
func TestGetMFASecretProxy_InvalidUserIDQuery_S21(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/mfa/secrets?user_id=notanint", nil)
	w := httptest.NewRecorder()
	h.GetMFASecretProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── CountUnusedMFARecoveryCodesProxy: invalid user_id query ──────────────────

// TestCountUnusedMFARecoveryCodesProxy_InvalidUserIDQuery_S21 — user_id is
// present but non-integer → 400.
func TestCountUnusedMFARecoveryCodesProxy_InvalidUserIDQuery_S21(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/mfa/recovery-codes/count?user_id=notanint", nil)
	w := httptest.NewRecorder()
	h.CountUnusedMFARecoveryCodesProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── CountUnusedMFARecoveryCodesProxy: happy path ─────────────────────────────

// TestCountUnusedMFARecoveryCodesProxy_HappyPath_S21 — user exists, no codes
// → count = 0 → 200.
func TestCountUnusedMFARecoveryCodesProxy_HappyPath_S21(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/mfa/recovery-codes/count?user_id=1", nil)
	w := httptest.NewRecorder()
	h.CountUnusedMFARecoveryCodesProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Success bool           `json:"success"`
		Data    map[string]int `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
	assert.Equal(t, 0, resp.Data["count"])
}
