// openapi_contract_adr112_mfa_test.go — ADR-112 item 1 follow-up: the CLI now
// drives mfaEnroll/mfaActivate/mfaVerify end to end (see cli/cmd/mfa.go,
// cli/cmd/login.go), so their newly-added openapi.yaml response schemas must
// move from "pending" to genuinely enforced, same precedent as
// openapi_contract_pr1_test.go. Reuses mfa_stepup_handler_test.go's own
// encryptor-equipped fixture rather than building a second one.
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

	"github.com/keyorixhq/keyorix/server/http/handlers/contracttest"
)

func TestContractADR112_MFAEnrollActivateVerify(t *testing.T) {
	h, coreService, _ := setupMFAStepUpTest(t)

	enrollReq := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/enroll", nil))
	w := httptest.NewRecorder()
	h.EnrollMFA(w, enrollReq)
	contracttest.AssertOpenAPIResponse(t, enrollReq, w)
	require.Equal(t, http.StatusOK, w.Code)

	var enrollResp struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &enrollResp))
	require.NotEmpty(t, enrollResp.Data.Secret)

	activateCode, err := totp.GenerateCode(enrollResp.Data.Secret, time.Now())
	require.NoError(t, err)
	activateBody, _ := json.Marshal(map[string]string{"code": activateCode, "password": stepUpTestPassword})
	activateReq := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/activate", bytes.NewReader(activateBody)))
	activateReq.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ActivateMFA(w, activateReq)
	contracttest.AssertOpenAPIResponse(t, activateReq, w)
	require.Equal(t, http.StatusOK, w.Code)

	var activateResp struct {
		Data struct {
			RecoveryCodes []string `json:"recovery_codes"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &activateResp))
	require.NotEmpty(t, activateResp.Data.RecoveryCodes)

	challenge, err := coreService.CreateMFAChallenge(context.Background(), 1)
	require.NoError(t, err)
	// ActivateMFA consumed the TOTP step it just checked (anti-replay); step
	// forward one period so this code is fresh rather than refused as reused.
	verifyCode, err := totp.GenerateCode(enrollResp.Data.Secret, time.Now().Add(30*time.Second))
	require.NoError(t, err)
	verifyBody, _ := json.Marshal(map[string]string{"mfa_challenge": challenge, "code": verifyCode})
	verifyReq := httptest.NewRequest(http.MethodPost, "/auth/mfa/verify", bytes.NewReader(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.VerifyMFA(w, verifyReq)
	contracttest.AssertOpenAPIResponse(t, verifyReq, w)
	require.Equal(t, http.StatusOK, w.Code)

	var verifyResp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &verifyResp))
	require.NotEmpty(t, verifyResp.Data.Token)
}
