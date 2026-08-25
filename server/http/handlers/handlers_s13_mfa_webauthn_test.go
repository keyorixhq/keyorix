// handlers_s13_mfa_webauthn_test.go — coverage sweep for mfa.go,
// mfa_management_proxy.go, webauthn.go, and webauthn_proxy.go.
// Targets uncovered branches:
//   - mfa.go: no-user-context (401), bad JSON (400), core-error (400) for every
//     self-service handler; VerifyMFA bad JSON + core error (401)
//   - mfa_management_proxy.go: missing/invalid params (400), invalid JSON (400),
//     validation errors (400), not-found (404) for GetMFASecretProxy
//   - webauthn.go: no-user-context (401), bad JSON (400), empty credential (400),
//     bad attestation/assertion (400), core error (400/501), bad id param (400)
//   - webauthn_proxy.go: missing/invalid params (400), invalid JSON (400),
//     validation errors (400), not-found (404) paths
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
)

// ── MFA self-service handlers (mfa.go) ───────────────────────────────────────

// TestEnrollMFA_NoUserCtx_S13 — no user context → 401.
func TestEnrollMFA_NoUserCtx_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/enroll", nil)
	w := httptest.NewRecorder()
	h.EnrollMFA(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestActivateMFA_NoUserCtx_S13 — no user context → 401.
func TestActivateMFA_NoUserCtx_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/activate", nil)
	w := httptest.NewRecorder()
	h.ActivateMFA(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestActivateMFA_BadJSON_S13 — malformed body → 400.
func TestActivateMFA_BadJSON_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/activate", bytes.NewBufferString("not-json"))
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.ActivateMFA(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDisableMFA_NoUserCtx_S13 — no user context → 401.
func TestDisableMFA_NoUserCtx_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/disable", nil)
	w := httptest.NewRecorder()
	h.DisableMFA(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDisableMFA_BadJSON_S13 — malformed body → 400.
func TestDisableMFA_BadJSON_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/disable", bytes.NewBufferString("not-json"))
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.DisableMFA(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDisableMFA_CoreError_S13 — MFA not enabled → 400 from core.
func TestDisableMFA_CoreError_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	body, _ := json.Marshal(map[string]string{"code": "000000"})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/disable", bytes.NewReader(body))
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.DisableMFA(w, r)
	// Core returns an error because MFA is not enrolled for user 1.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRegenerateRecoveryCodes_NoUserCtx_S13 — no user context → 401.
func TestRegenerateRecoveryCodes_NoUserCtx_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/recovery-codes/regenerate", nil)
	w := httptest.NewRecorder()
	h.RegenerateRecoveryCodes(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRegenerateRecoveryCodes_BadJSON_S13 — malformed body → 400.
func TestRegenerateRecoveryCodes_BadJSON_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/recovery-codes/regenerate", bytes.NewBufferString("not-json"))
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.RegenerateRecoveryCodes(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRegenerateRecoveryCodes_CoreError_S13 — MFA not enabled → 400 from core.
func TestRegenerateRecoveryCodes_CoreError_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	body, _ := json.Marshal(map[string]string{"code": "000000"})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/recovery-codes/regenerate", bytes.NewReader(body))
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.RegenerateRecoveryCodes(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRecoveryCodesStatus_NoUserCtx_S13 — no user context → 401.
func TestRecoveryCodesStatus_NoUserCtx_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/mfa/recovery-codes/status", nil)
	w := httptest.NewRecorder()
	h.RecoveryCodesStatus(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRecoveryCodesStatus_CoreError_S13 — user not found → 400 from core.
func TestRecoveryCodesStatus_CoreError_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/mfa/recovery-codes/status", nil)
	// UserID 9999 does not exist → MFARecoveryCodesRemaining returns "user not found" → 400.
	r = withUserContext(r, 9999)
	w := httptest.NewRecorder()
	h.RecoveryCodesStatus(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestVerifyMFA_BadJSON_S13 — malformed body → 400.
func TestVerifyMFA_BadJSON_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewBufferString("not-json"))
	w := httptest.NewRecorder()
	h.VerifyMFA(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestVerifyMFA_InvalidChallenge_S13 — bad challenge → 401 from core.
func TestVerifyMFA_InvalidChallenge_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	body, _ := json.Marshal(map[string]string{
		"mfa_challenge": "invalid-challenge-token",
		"code":          "123456",
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.VerifyMFA(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── WebAuthn self-service handlers (webauthn.go) ─────────────────────────────

// TestBeginWebAuthnRegistration_NoUserCtx_S13 — no user context → 401.
func TestBeginWebAuthnRegistration_NoUserCtx_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/register/begin", nil)
	w := httptest.NewRecorder()
	h.BeginWebAuthnRegistration(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestFinishWebAuthnRegistration_NoUserCtx_S13 — no user context → 401.
func TestFinishWebAuthnRegistration_NoUserCtx_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/register/finish", nil)
	w := httptest.NewRecorder()
	h.FinishWebAuthnRegistration(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestFinishWebAuthnRegistration_BadJSON_S13 — malformed JSON → 400.
func TestFinishWebAuthnRegistration_BadJSON_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/register/finish", bytes.NewBufferString("not-json"))
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.FinishWebAuthnRegistration(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestFinishWebAuthnRegistration_EmptyCredential_S13 — valid JSON but missing
// credential field → 400.
func TestFinishWebAuthnRegistration_EmptyCredential_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	body, _ := json.Marshal(map[string]interface{}{
		"webauthn_session": "some-session",
		"name":             "laptop",
		// credential intentionally omitted
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/register/finish", bytes.NewReader(body))
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.FinishWebAuthnRegistration(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestFinishWebAuthnRegistration_InvalidAttestation_S13 — structurally invalid
// credential blob → 400 "Invalid attestation".
func TestFinishWebAuthnRegistration_InvalidAttestation_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	body, _ := json.Marshal(map[string]interface{}{
		"webauthn_session": "some-session",
		"name":             "laptop",
		"credential":       json.RawMessage(`{"type":"public-key","id":"invalid"}`),
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/register/finish", bytes.NewReader(body))
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.FinishWebAuthnRegistration(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListWebAuthnCredentials_NoUserCtx_S13 — no user context → 401.
func TestListWebAuthnCredentials_NoUserCtx_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/webauthn/credentials", nil)
	w := httptest.NewRecorder()
	h.ListWebAuthnCredentials(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDeleteWebAuthnCredential_NoUserCtx_S13 — no user context → 401.
func TestDeleteWebAuthnCredential_NoUserCtx_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/webauthn/credentials/1", nil)
	r = withChiParams(r, map[string]string{"id": "1"})
	w := httptest.NewRecorder()
	h.DeleteWebAuthnCredential(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDeleteWebAuthnCredential_BadIDParam_S13 — non-numeric id param → 400.
func TestDeleteWebAuthnCredential_BadIDParam_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/webauthn/credentials/bad", nil)
	r = withUserContext(r, 1)
	r = withChiParams(r, map[string]string{"id": "bad"})
	w := httptest.NewRecorder()
	h.DeleteWebAuthnCredential(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeleteWebAuthnCredential_BadJSON_S13 — malformed JSON in body → 400.
func TestDeleteWebAuthnCredential_BadJSON_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/webauthn/credentials/1",
		bytes.NewBufferString("{not valid json"))
	r = withUserContext(r, 1)
	r = withChiParams(r, map[string]string{"id": "1"})
	w := httptest.NewRecorder()
	h.DeleteWebAuthnCredential(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestBeginWebAuthnLogin_BadJSON_S13 — malformed body → 400.
func TestBeginWebAuthnLogin_BadJSON_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/login/begin",
		bytes.NewBufferString("not-json"))
	w := httptest.NewRecorder()
	h.BeginWebAuthnLogin(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestBeginWebAuthnLogin_InvalidChallenge_S13 — bad challenge → core error → 400.
func TestBeginWebAuthnLogin_InvalidChallenge_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	body, _ := json.Marshal(map[string]string{"mfa_challenge": "bad-challenge"})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/login/begin",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.BeginWebAuthnLogin(w, r)
	// Core fails to find the challenge → 400 (non-disabled error via writeWebAuthnErr).
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestFinishWebAuthnLogin_BadJSON_S13 — malformed body → 400.
func TestFinishWebAuthnLogin_BadJSON_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/login/finish",
		bytes.NewBufferString("not-json"))
	w := httptest.NewRecorder()
	h.FinishWebAuthnLogin(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestFinishWebAuthnLogin_EmptyCredential_S13 — valid JSON, missing credential → 400.
func TestFinishWebAuthnLogin_EmptyCredential_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	body, _ := json.Marshal(map[string]interface{}{
		"mfa_challenge":    "ch",
		"webauthn_session": "sess",
		// credential omitted
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/login/finish",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.FinishWebAuthnLogin(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestFinishWebAuthnLogin_InvalidAssertion_S13 — structurally invalid credential → 400.
func TestFinishWebAuthnLogin_InvalidAssertion_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	body, _ := json.Marshal(map[string]interface{}{
		"mfa_challenge":    "ch",
		"webauthn_session": "sess",
		"credential":       json.RawMessage(`{"type":"public-key","id":"garbage"}`),
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/login/finish",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.FinishWebAuthnLogin(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestBeginWebAuthnPasswordlessLogin_Disabled_S13 — WebAuthn not configured →
// should return 501 (ErrWebAuthnDisabled via writeWebAuthnErr).
func TestBeginWebAuthnPasswordlessLogin_Disabled_S13(t *testing.T) {
	// Use a core WITHOUT a WebAuthn RP set up; core returns ErrWebAuthnDisabled.
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/passwordless/begin", nil)
	w := httptest.NewRecorder()
	h.BeginWebAuthnPasswordlessLogin(w, r)
	// writeWebAuthnErr maps ErrWebAuthnDisabled → 501 Not Implemented.
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

// TestFinishWebAuthnPasswordlessLogin_BadJSON_S13 — malformed body → 400.
func TestFinishWebAuthnPasswordlessLogin_BadJSON_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/passwordless/finish",
		bytes.NewBufferString("not-json"))
	w := httptest.NewRecorder()
	h.FinishWebAuthnPasswordlessLogin(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestFinishWebAuthnPasswordlessLogin_EmptyCredential_S13 — valid JSON, missing credential → 400.
func TestFinishWebAuthnPasswordlessLogin_EmptyCredential_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	body, _ := json.Marshal(map[string]interface{}{
		"webauthn_session": "sess",
		// credential omitted
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/passwordless/finish",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.FinishWebAuthnPasswordlessLogin(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestFinishWebAuthnPasswordlessLogin_InvalidAssertion_S13 — invalid credential blob → 400.
func TestFinishWebAuthnPasswordlessLogin_InvalidAssertion_S13(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)
	body, _ := json.Marshal(map[string]interface{}{
		"webauthn_session": "sess",
		"credential":       json.RawMessage(`{"type":"public-key","id":"garbage"}`),
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/webauthn/passwordless/finish",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.FinishWebAuthnPasswordlessLogin(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── MFA management proxy handlers (mfa_management_proxy.go) ──────────────────

// TestGetMFASecretProxy_MissingUserID_S13 — missing user_id query param → 400.
func TestGetMFASecretProxy_MissingUserID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/mfa/secrets", nil)
	w := httptest.NewRecorder()
	h.GetMFASecretProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetMFASecretProxy_InvalidUserID_S13 — non-numeric user_id → 400.
func TestGetMFASecretProxy_InvalidUserID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/mfa/secrets?user_id=bad", nil)
	w := httptest.NewRecorder()
	h.GetMFASecretProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetMFASecretProxy_NotFound_S13 — valid user_id but no MFA secret → 404.
func TestGetMFASecretProxy_NotFound_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/mfa/secrets?user_id=9999", nil)
	w := httptest.NewRecorder()
	h.GetMFASecretProxy(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestActivateMFASecretProxy_BadIDParam_S13 — invalid userId path param → 400.
func TestActivateMFASecretProxy_BadIDParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/secrets/bad/activate", nil)
	r = withChiParams(r, map[string]string{"userId": "bad"})
	w := httptest.NewRecorder()
	h.ActivateMFASecretProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeleteMFAForUserProxy_BadIDParam_S13 — invalid userId path param → 400.
func TestDeleteMFAForUserProxy_BadIDParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/system/mfa/users/bad", nil)
	r = withChiParams(r, map[string]string{"userId": "bad"})
	w := httptest.NewRecorder()
	h.DeleteMFAForUserProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSetUserMFAEnabledProxy_BadIDParam_S13 — invalid userId path param → 400.
func TestSetUserMFAEnabledProxy_BadIDParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodPut, "/api/v1/system/mfa/users/bad/mfa-enabled", nil)
	r = withChiParams(r, map[string]string{"userId": "bad"})
	w := httptest.NewRecorder()
	h.SetUserMFAEnabledProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSetUserMFAEnabledProxy_BadJSON_S13 — valid id but malformed body → 400.
func TestSetUserMFAEnabledProxy_BadJSON_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodPut, "/api/v1/system/mfa/users/1/mfa-enabled",
		bytes.NewBufferString("not-json"))
	r = withChiParams(r, map[string]string{"userId": "1"})
	w := httptest.NewRecorder()
	h.SetUserMFAEnabledProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateMFARecoveryCodesProxy_MissingUserID_S13 — missing user_id → 400.
func TestCreateMFARecoveryCodesProxy_MissingUserID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/recovery-codes", nil)
	w := httptest.NewRecorder()
	h.CreateMFARecoveryCodesProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateMFARecoveryCodesProxy_BadJSON_S13 — valid user_id but bad JSON → 400.
func TestCreateMFARecoveryCodesProxy_BadJSON_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/recovery-codes?user_id=1",
		bytes.NewBufferString("not-json"))
	w := httptest.NewRecorder()
	h.CreateMFARecoveryCodesProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCountUnusedMFARecoveryCodesProxy_MissingUserID_S13 — missing user_id → 400.
func TestCountUnusedMFARecoveryCodesProxy_MissingUserID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/mfa/recovery-codes/count", nil)
	w := httptest.NewRecorder()
	h.CountUnusedMFARecoveryCodesProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCountUnusedMFARecoveryCodesProxy_InvalidUserID_S13 — non-numeric user_id → 400.
func TestCountUnusedMFARecoveryCodesProxy_InvalidUserID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/mfa/recovery-codes/count?user_id=abc", nil)
	w := httptest.NewRecorder()
	h.CountUnusedMFARecoveryCodesProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeleteMFARecoveryCodesProxy_BadIDParam_S13 — invalid userId path param → 400.
func TestDeleteMFARecoveryCodesProxy_BadIDParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/system/mfa/recovery-codes/bad", nil)
	r = withChiParams(r, map[string]string{"userId": "bad"})
	w := httptest.NewRecorder()
	h.DeleteMFARecoveryCodesProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── WebAuthn proxy handlers (webauthn_proxy.go) ───────────────────────────────

// TestListWebAuthnCredentialsProxy_MissingUserID_S13 — missing user_id → 400.
func TestListWebAuthnCredentialsProxy_MissingUserID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/webauthn/credentials", nil)
	w := httptest.NewRecorder()
	h.ListWebAuthnCredentialsProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListWebAuthnCredentialsProxy_InvalidUserID_S13 — non-numeric user_id → 400.
func TestListWebAuthnCredentialsProxy_InvalidUserID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/webauthn/credentials?user_id=bad", nil)
	w := httptest.NewRecorder()
	h.ListWebAuthnCredentialsProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetWebAuthnCredentialByCredIDProxy_MissingUserID_S13 — missing user_id → 400.
func TestGetWebAuthnCredentialByCredIDProxy_MissingUserID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/webauthn/credentials/lookup", nil)
	w := httptest.NewRecorder()
	h.GetWebAuthnCredentialByCredIDProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetWebAuthnCredentialByCredIDProxy_MissingCredID_S13 — user_id ok but
// missing credential_id → 400.
func TestGetWebAuthnCredentialByCredIDProxy_MissingCredID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/webauthn/credentials/lookup?user_id=1", nil)
	w := httptest.NewRecorder()
	h.GetWebAuthnCredentialByCredIDProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetWebAuthnCredentialByCredIDProxy_InvalidBase64_S13 — credential_id that
// isn't valid base64 → 400.
func TestGetWebAuthnCredentialByCredIDProxy_InvalidBase64_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/webauthn/credentials/lookup?user_id=1&credential_id=!!not-base64!!", nil)
	w := httptest.NewRecorder()
	h.GetWebAuthnCredentialByCredIDProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetWebAuthnCredentialByCredIDProxy_NotFound_S13 — valid params but cred
// doesn't exist → 404.
func TestGetWebAuthnCredentialByCredIDProxy_NotFound_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	// base64("test") = "dGVzdA=="
	r := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/webauthn/credentials/lookup?user_id=1&credential_id=dGVzdA==", nil)
	w := httptest.NewRecorder()
	h.GetWebAuthnCredentialByCredIDProxy(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestUpdateWebAuthnCredentialProxy_BadIDParam_S13 — non-numeric id → 400.
func TestUpdateWebAuthnCredentialProxy_BadIDParam_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodPut, "/api/v1/system/webauthn/credentials/bad",
		bytes.NewBufferString("{}"))
	r = withChiParams(r, map[string]string{"id": "bad"})
	w := httptest.NewRecorder()
	h.UpdateWebAuthnCredentialProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateWebAuthnCredentialProxy_BadJSON_S13 — valid id but malformed JSON → 400.
func TestUpdateWebAuthnCredentialProxy_BadJSON_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodPut, "/api/v1/system/webauthn/credentials/1",
		bytes.NewBufferString("not-json"))
	r = withChiParams(r, map[string]string{"id": "1"})
	w := httptest.NewRecorder()
	h.UpdateWebAuthnCredentialProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestAdvanceWebAuthnCredentialCounterProxy_BadJSON_S13 — malformed JSON → 400.
func TestAdvanceWebAuthnCredentialCounterProxy_BadJSON_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodPatch, "/api/v1/system/webauthn/credentials/advance-counter",
		bytes.NewBufferString("not-json"))
	w := httptest.NewRecorder()
	h.AdvanceWebAuthnCredentialCounterProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestAdvanceWebAuthnCredentialCounterProxy_MissingFields_S13 — missing required
// fields → 400.
func TestAdvanceWebAuthnCredentialCounterProxy_MissingFields_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	// Only user_id set, credential_id and new_blob are missing/empty.
	body, _ := json.Marshal(map[string]interface{}{"user_id": 1})
	r := httptest.NewRequest(http.MethodPatch, "/api/v1/system/webauthn/credentials/advance-counter",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.AdvanceWebAuthnCredentialCounterProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCountWebAuthnCredentialsProxy_MissingUserID_S13 — missing user_id → 400.
func TestCountWebAuthnCredentialsProxy_MissingUserID_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/webauthn/credentials/count", nil)
	w := httptest.NewRecorder()
	h.CountWebAuthnCredentialsProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateWebAuthnSessionProxy_BadJSON_S13 — malformed JSON → 400.
func TestCreateWebAuthnSessionProxy_BadJSON_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/webauthn/sessions",
		bytes.NewBufferString("not-json"))
	w := httptest.NewRecorder()
	h.CreateWebAuthnSessionProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateWebAuthnSessionProxy_MissingFields_S13 — missing user_id/token_hash → 400.
func TestCreateWebAuthnSessionProxy_MissingFields_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	body, _ := json.Marshal(map[string]interface{}{"user_id": 0})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/webauthn/sessions",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateWebAuthnSessionProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestConsumeWebAuthnSessionProxy_BadJSON_S13 — malformed JSON → 400.
func TestConsumeWebAuthnSessionProxy_BadJSON_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/webauthn/sessions/consume",
		bytes.NewBufferString("not-json"))
	w := httptest.NewRecorder()
	h.ConsumeWebAuthnSessionProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestConsumeWebAuthnSessionProxy_MissingFields_S13 — missing token_hash/now → 400.
func TestConsumeWebAuthnSessionProxy_MissingFields_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	body, _ := json.Marshal(map[string]interface{}{"token_hash": ""})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/webauthn/sessions/consume",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ConsumeWebAuthnSessionProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestConsumeWebAuthnSessionProxy_NotFound_S13 — valid body but no matching
// session → 404.
func TestConsumeWebAuthnSessionProxy_NotFound_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)
	body, _ := json.Marshal(map[string]interface{}{
		"token_hash": "nonexistent-hash",
		"now":        "2026-01-01T00:00:00Z",
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/webauthn/sessions/consume",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ConsumeWebAuthnSessionProxy(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestConsumeWebAuthnSessionProxy_SecondConsumeFails is the G80 documented-
// exception re-verification sweep's regression test for the "holds" verdict on
// this handler's single-use claim (raw_storage_bypass_guard_test.go): the
// underlying conditional UPDATE (local_webauthn.go) must actually be single-
// use, not just described as such. A second consume of the SAME token_hash
// must fail — a second success would mean the CAS isn't real.
func TestConsumeWebAuthnSessionProxy_SecondConsumeFails(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)

	createBody, _ := json.Marshal(map[string]interface{}{
		"user_id":    1,
		"token_hash": "single-use-webauthn-session",
		"purpose":    "registration",
		"expires_at": time.Now().Add(time.Hour).UTC(),
	})
	r0 := httptest.NewRequest(http.MethodPost, "/api/v1/system/webauthn/sessions", bytes.NewReader(createBody))
	w0 := httptest.NewRecorder()
	h.CreateWebAuthnSessionProxy(w0, r0)
	require.Equal(t, http.StatusOK, w0.Code)

	consumeBody, _ := json.Marshal(map[string]interface{}{
		"token_hash": "single-use-webauthn-session",
		"now":        time.Now().UTC().Format(time.RFC3339),
	})
	r1 := httptest.NewRequest(http.MethodPost, "/api/v1/system/webauthn/sessions/consume", bytes.NewReader(consumeBody))
	w1 := httptest.NewRecorder()
	h.ConsumeWebAuthnSessionProxy(w1, r1)
	require.Equal(t, http.StatusOK, w1.Code, "first consume must succeed")

	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/system/webauthn/sessions/consume", bytes.NewReader(consumeBody))
	w2 := httptest.NewRecorder()
	h.ConsumeWebAuthnSessionProxy(w2, r2)
	assert.NotEqual(t, http.StatusOK, w2.Code,
		"CEILING VIOLATED: a second consume of an already-consumed WebAuthn session must fail — the conditional "+
			"UPDATE this handler relies on for its single-use guarantee is not actually a CAS if this succeeds")
}
