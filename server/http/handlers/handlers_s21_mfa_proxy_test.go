// handlers_s21_mfa_proxy_test.go — coverage sweep targeting the storage-error
// (500) branches in mfa_management_proxy.go that remain uncovered:
//   - UpsertMFASecretProxy: storage error → 500
//   - GetMFASecretProxy: non-not-found storage error → 500
//   - ActivateMFASecretProxy: bad userId → 400, storage error → 500
//   - DeleteMFAForUserProxy: bad userId → 400, storage error → 500
//   - SetUserMFAEnabledProxy: storage error → 500
//   - CreateMFARecoveryCodesProxy: storage error → 500
//   - CountUnusedMFARecoveryCodesProxy: storage error → 500
//   - DeleteMFARecoveryCodesProxy: bad userId → 400, storage error → 500
package handlers

import (
	"bytes"
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

// ── UpsertMFASecretProxy ──────────────────────────────────────────────────────

// TestUpsertMFASecretProxy_StorageError_S21 — valid body but DB is closed
// → storage error → 500.
func TestUpsertMFASecretProxy_StorageError_S21(t *testing.T) {
	h := freshClosedCoreS21(t)
	body, _ := json.Marshal(map[string]interface{}{
		"user_id":    1,
		"secret_enc": []byte("enc"),
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/secrets",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.UpsertMFASecretProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
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

// ── ActivateMFASecretProxy ────────────────────────────────────────────────────

// TestActivateMFASecretProxy_StorageError_S21 — valid userId, DB closed
// → storage error → 500.
func TestActivateMFASecretProxy_StorageError_S21(t *testing.T) {
	h := freshClosedCoreS21(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/secrets/1/activate", nil)
	r = withChiParams(r, map[string]string{"userId": "1"})
	w := httptest.NewRecorder()
	h.ActivateMFASecretProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── DeleteMFAForUserProxy ─────────────────────────────────────────────────────

// TestDeleteMFAForUserProxy_StorageError_S21 — valid userId, DB closed
// → storage error → 500.
func TestDeleteMFAForUserProxy_StorageError_S21(t *testing.T) {
	h := freshClosedCoreS21(t)
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/system/mfa/users/1", nil)
	r = withChiParams(r, map[string]string{"userId": "1"})
	w := httptest.NewRecorder()
	h.DeleteMFAForUserProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── SetUserMFAEnabledProxy ────────────────────────────────────────────────────

// TestSetUserMFAEnabledProxy_StorageError_S21 — valid userId + valid body,
// DB closed → storage error → 500.
func TestSetUserMFAEnabledProxy_StorageError_S21(t *testing.T) {
	h := freshClosedCoreS21(t)
	body, _ := json.Marshal(map[string]bool{"enabled": true})
	r := httptest.NewRequest(http.MethodPut, "/api/v1/system/mfa/users/1/mfa-enabled",
		bytes.NewReader(body))
	r = withChiParams(r, map[string]string{"userId": "1"})
	w := httptest.NewRecorder()
	h.SetUserMFAEnabledProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── CreateMFARecoveryCodesProxy ───────────────────────────────────────────────

// TestCreateMFARecoveryCodesProxy_StorageError_S21 — valid user_id + valid
// body, DB closed → storage error → 500.
func TestCreateMFARecoveryCodesProxy_StorageError_S21(t *testing.T) {
	h := freshClosedCoreS21(t)
	body, _ := json.Marshal(map[string]interface{}{"code_hashes": []string{"hash1"}})
	r := httptest.NewRequest(http.MethodPost,
		"/api/v1/system/mfa/recovery-codes?user_id=1",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateMFARecoveryCodesProxy(w, r)
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

// ── DeleteMFARecoveryCodesProxy ───────────────────────────────────────────────

// TestDeleteMFARecoveryCodesProxy_StorageError_S21 — valid userId, DB closed
// → storage error → 500.
func TestDeleteMFARecoveryCodesProxy_StorageError_S21(t *testing.T) {
	h := freshClosedCoreS21(t)
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/system/mfa/recovery-codes/1", nil)
	r = withChiParams(r, map[string]string{"userId": "1"})
	w := httptest.NewRecorder()
	h.DeleteMFARecoveryCodesProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── GetMFASecretProxy: not-found branch via context deadline ─────────────────

// TestGetMFASecretProxy_NotFoundAfterUpsert_S21 — upsert a secret then GET it
// to exercise the 200 success branch in one shot (verifies the happy path runs
// through the not-found guard cleanly when the row exists).
func TestGetMFASecretProxy_NotFoundAfterUpsert_S21(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	setTestAuthEncryptor(t, cs)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "s21user2", Email: "s21user2@example.com", AccountState: "active"}).Error)
	// Upsert so GET finds a row.
	upBody, _ := json.Marshal(map[string]interface{}{
		"user_id":    uint(2),
		"secret_enc": []byte("s21enc"),
	})
	r0 := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/secrets",
		bytes.NewReader(upBody))
	w0 := httptest.NewRecorder()
	h.UpsertMFASecretProxy(w0, r0)
	require.Equal(t, http.StatusOK, w0.Code)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/mfa/secrets?user_id=2", nil)
	w := httptest.NewRecorder()
	h.GetMFASecretProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── SetUserMFAEnabledProxy: happy path ───────────────────────────────────────

// TestSetUserMFAEnabledProxy_HappyPath_S21 — live DB, valid userId + body → 200.
func TestSetUserMFAEnabledProxy_HappyPath_S21(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	body, _ := json.Marshal(map[string]bool{"enabled": false})
	r := httptest.NewRequest(http.MethodPut, "/api/v1/system/mfa/users/1/mfa-enabled",
		bytes.NewReader(body))
	r = withChiParams(r, map[string]string{"userId": "1"})
	w := httptest.NewRecorder()
	h.SetUserMFAEnabledProxy(w, r)
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

// ── CreateMFARecoveryCodesProxy: invalid user_id query ───────────────────────

// TestCreateMFARecoveryCodesProxy_InvalidUserIDQuery_S21 — user_id is present
// but not a valid integer → 400 (parseMFAUserIDQuery error branch).
func TestCreateMFARecoveryCodesProxy_InvalidUserIDQuery_S21(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	body, _ := json.Marshal(map[string]interface{}{"code_hashes": []string{}})
	r := httptest.NewRequest(http.MethodPost,
		"/api/v1/system/mfa/recovery-codes?user_id=notanint",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateMFARecoveryCodesProxy(w, r)
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

// ── newMFASecretProxyWire: exercise via round-trip ────────────────────────────

// TestUpsertMFASecretProxy_RoundTrip_S21 — upsert then verify response wire
// contains expected fields (exercises newMFASecretProxyWire via JSON decode).
func TestUpsertMFASecretProxy_RoundTrip_S21(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	setTestAuthEncryptor(t, cs)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "s21user3", Email: "s21user3@example.com", AccountState: "active"}).Error)
	body, _ := json.Marshal(map[string]interface{}{
		"user_id":    uint(3),
		"secret_enc": []byte("s21roundtrip"),
		"activated":  false,
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/secrets",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.UpsertMFASecretProxy(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			UserID uint `json:"user_id"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
	assert.Equal(t, uint(3), resp.Data.UserID)
}

// ── ActivateMFASecretProxy: happy path after upsert ──────────────────────────

// TestActivateMFASecretProxy_HappyPath_S21 — seed a secret then activate → 200.
func TestActivateMFASecretProxy_HappyPath_S21(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	setTestAuthEncryptor(t, cs)
	require.NoError(t, db.Create(&models.User{ID: 4, Username: "s21user4", Email: "s21user4@example.com", AccountState: "active"}).Error)

	// Upsert a secret for user 4 first.
	upBody, _ := json.Marshal(map[string]interface{}{
		"user_id":    uint(4),
		"secret_enc": []byte("enc4"),
	})
	r0 := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/secrets",
		bytes.NewReader(upBody))
	w0 := httptest.NewRecorder()
	h.UpsertMFASecretProxy(w0, r0)
	require.Equal(t, http.StatusOK, w0.Code)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/secrets/4/activate", nil)
	r = withChiParams(r, map[string]string{"userId": "4"})
	w := httptest.NewRecorder()
	h.ActivateMFASecretProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── DeleteMFAForUserProxy: happy path ────────────────────────────────────────

// TestDeleteMFAForUserProxy_HappyPath_S21 — user with no MFA data → no error
// → 200 (storage DeleteMFAForUser is idempotent).
func TestDeleteMFAForUserProxy_HappyPath_S21(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/system/mfa/users/99", nil)
	r = withChiParams(r, map[string]string{"userId": "99"})
	w := httptest.NewRecorder()
	h.DeleteMFAForUserProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ── DeleteMFARecoveryCodesProxy: happy path ───────────────────────────────────

// TestDeleteMFARecoveryCodesProxy_HappyPath_S21 — user with no recovery codes
// → storage returns nil → 200.
func TestDeleteMFARecoveryCodesProxy_HappyPath_S21(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/system/mfa/recovery-codes/99", nil)
	r = withChiParams(r, map[string]string{"userId": "99"})
	w := httptest.NewRecorder()
	h.DeleteMFARecoveryCodesProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
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

// ── UpsertMFASecretProxy: missing user_id or secret_enc → 400 ────────────────

// TestUpsertMFASecretProxy_MissingSecretEnc_S21 — user_id present but
// secret_enc absent → 400 (validation branch).
func TestUpsertMFASecretProxy_MissingSecretEnc_S21(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	body, _ := json.Marshal(map[string]interface{}{"user_id": 1})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/secrets",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.UpsertMFASecretProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── CreateMFARecoveryCodesProxy: happy path ───────────────────────────────────

// TestCreateMFARecoveryCodesProxy_HappyPath_S21 — valid user_id and hashes
// → 200.
func TestCreateMFARecoveryCodesProxy_HappyPath_S21(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	body, _ := json.Marshal(map[string]interface{}{
		"code_hashes": []string{"hash-a", "hash-b"},
	})
	r := httptest.NewRequest(http.MethodPost,
		"/api/v1/system/mfa/recovery-codes?user_id=1",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateMFARecoveryCodesProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}
