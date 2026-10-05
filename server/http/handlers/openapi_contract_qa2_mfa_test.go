// openapi_contract_qa2_mfa_test.go closes a real contract gap found while
// investigating the bug class behind #2441/#2442 (QA-2 session): the
// self-service MFA lifecycle endpoints (enroll/activate/disable/
// recovery-codes/regenerate), the mfa_required branch of /auth/login, and
// the /auth/mfa/verify completion step all existed in the router and were
// called by the web app, but had NO operation at all in openapi.yaml -- not
// even a pending entry (ADR-074's partition invariant never saw them). A
// generated TypeScript client built from the spec could not have required
// activateMFA's password field, because the spec had no requestBody for it
// whatsoever -- which is exactly how #2441 (enrollment never sent the
// password ActivateMFA requires) shipped. These tests exercise each
// new/changed operation through AssertOpenAPIResponse so registry.go's
// exercisingTests accepts them as enforced-and-exercised, not just declared.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

func TestContractQA2_EnrollMFA(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/enroll", nil)
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.EnrollMFA(w, r)

	contracttest.AssertOpenAPIResponse(t, r, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractQA2_ActivateMFA(t *testing.T) {
	h, coreService, _ := setupMFAReauthTest(t)
	fixed := time.Now()

	_, secret, err := coreService.BeginMFAEnrollment(context.Background(), 1)
	require.NoError(t, err)
	code, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{"code": code, "password": reauthTestPassword})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/activate", bytes.NewReader(body))
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.ActivateMFA(w, r)

	contracttest.AssertOpenAPIResponse(t, r, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractQA2_DisableMFA(t *testing.T) {
	h, coreService, _ := setupMFAReauthTest(t)
	fixed := time.Now()

	_, secret, err := coreService.BeginMFAEnrollment(context.Background(), 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = coreService.ActivateMFA(context.Background(), 1, actCode, reauthTestPassword, "")
	require.NoError(t, err)

	// A step away from the activation code (above) so this isn't a replay of
	// the exact same TOTP value within the ±1 step anti-replay window.
	disableCode, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{"code": disableCode})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/disable", bytes.NewReader(body))
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.DisableMFA(w, r)

	contracttest.AssertOpenAPIResponse(t, r, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractQA2_RegenerateRecoveryCodes(t *testing.T) {
	h, coreService, _ := setupMFAReauthTest(t)
	fixed := time.Now()

	_, secret, err := coreService.BeginMFAEnrollment(context.Background(), 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = coreService.ActivateMFA(context.Background(), 1, actCode, reauthTestPassword, "")
	require.NoError(t, err)

	regenCode, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{"code": regenCode})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/recovery-codes/regenerate", bytes.NewReader(body))
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.RegenerateRecoveryCodes(w, r)

	contracttest.AssertOpenAPIResponse(t, r, w)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestContractQA2_RecoveryCodesStatus(t *testing.T) {
	h, _, _ := setupMFAReauthTest(t)

	// No enrolment needed -- the handler reports remaining=0/total=0 for an
	// account with no MFA secret at all.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/mfa/recovery-codes", nil)
	r = withUserContext(r, 1)
	w := httptest.NewRecorder()
	h.RecoveryCodesStatus(w, r)

	contracttest.AssertOpenAPIResponse(t, r, w)
	require.Equal(t, http.StatusOK, w.Code)
}

// TestContractQA2_Login_MFARequiredBranch exercises authLogin's OTHER
// response shape: a correct password on an MFA-enrolled account returns
// mfa_required (core.ErrMFARequired), not a session. This is the branch the
// web app's login flow silently ignored (#2442) -- the new
// MFAChallengeData oneOf member must actually validate against this real
// response, not just exist in the spec.
func TestContractQA2_Login_MFARequiredBranch(t *testing.T) {
	h, coreService, db := setupMFAReauthTest(t)
	fixed := time.Now()
	// setupMFAReauthTest creates the user via a raw db.Create, which -- unlike
	// core.CreateUser/BootstrapSystem -- never populates UsernameFolded (no
	// GORM hook computes it). Login looks the user up by that column, so it
	// must be backfilled here or every login in this test 401s as "not found"
	// before ever reaching the MFA-required branch under test.
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("username_folded", "alice").Error)

	_, secret, err := coreService.BeginMFAEnrollment(context.Background(), 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	_, err = coreService.ActivateMFA(context.Background(), 1, actCode, reauthTestPassword, "")
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{"username": "alice", "password": reauthTestPassword})
	r := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Login(w, r)

	contracttest.AssertOpenAPIResponse(t, r, w)
	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Data struct {
			MFARequired  bool   `json:"mfa_required"`
			MFAChallenge string `json:"mfa_challenge"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.True(t, resp.Data.MFARequired)
	require.NotEmpty(t, resp.Data.MFAChallenge)
}

// TestContractQA2_VerifyMFALogin completes the two-step login the web app's
// mfa_required branch is supposed to drive: a real /auth/login challenge,
// then /auth/mfa/verify with a fresh TOTP code, minting a real session.
func TestContractQA2_VerifyMFALogin(t *testing.T) {
	h, coreService, db := setupMFAReauthTest(t)
	// completeLogin resolves the user's roles and fails closed when it cannot (main, post-#2442),
	// so the login path needs the RBAC + login-throttle tables setupMFAReauthTest omits.
	require.NoError(t, db.AutoMigrate(&models.Role{}, &models.UserRole{}, &models.Permission{}, &models.RolePermission{}, &models.LoginAttempt{}))
	fixed := time.Now()
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).Update("username_folded", "alice").Error)

	_, secret, err := coreService.BeginMFAEnrollment(context.Background(), 1)
	require.NoError(t, err)
	actCode, err := totp.GenerateCode(secret, fixed.Add(-30*time.Second))
	require.NoError(t, err)
	_, err = coreService.ActivateMFA(context.Background(), 1, actCode, reauthTestPassword, "")
	require.NoError(t, err)

	loginBody, _ := json.Marshal(map[string]string{"username": "alice", "password": reauthTestPassword})
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(loginBody))
	loginW := httptest.NewRecorder()
	h.Login(loginW, loginReq)
	require.Equal(t, http.StatusOK, loginW.Code)

	var loginResp struct {
		Data struct {
			MFAChallenge string `json:"mfa_challenge"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(loginW.Body).Decode(&loginResp))
	require.NotEmpty(t, loginResp.Data.MFAChallenge)

	verifyCode, err := totp.GenerateCode(secret, fixed)
	require.NoError(t, err)
	verifyBody, _ := json.Marshal(map[string]string{
		"mfa_challenge": loginResp.Data.MFAChallenge,
		"code":          verifyCode,
	})
	verifyReq := httptest.NewRequest(http.MethodPost, "/auth/mfa/verify", bytes.NewReader(verifyBody))
	verifyW := httptest.NewRecorder()
	h.VerifyMFA(verifyW, verifyReq)

	contracttest.AssertOpenAPIResponse(t, verifyReq, verifyW)
	require.Equal(t, http.StatusOK, verifyW.Code)

	var verifyResp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(verifyW.Body).Decode(&verifyResp))
	require.NotEmpty(t, verifyResp.Data.Token)
}
