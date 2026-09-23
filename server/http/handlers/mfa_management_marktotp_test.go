// mfa_management_marktotp_test.go — coverage for MarkTOTPStepUsedProxy
// (mfa_management_proxy.go), previously untested (0% coverage): POST
// /api/v1/system/mfa/totp-step-used.
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

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// nowTOTPStep is the realistic "current" step value every fixture below uses
// in place of the old, arbitrary "5" — F6's step-bound fix
// (mfa_management_proxy.go) rejects any step far from this server's own
// clock, so a fixture using a tiny absolute number would now be refused by
// the bound check before ever reaching the behavior each test actually
// exercises.
func nowTOTPStep(t *testing.T) int64 {
	t.Helper()
	return time.Now().UTC().Unix() / totpStepPeriodSeconds
}

func TestMarkTOTPStepUsedProxy_BadJSON(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/totp-step-used",
		bytes.NewReader([]byte("{bad json}")))
	w := httptest.NewRecorder()
	h.MarkTOTPStepUsedProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMarkTOTPStepUsedProxy_MissingUserID(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	body, _ := json.Marshal(map[string]interface{}{"user_id": 0, "step": nowTOTPStep(t)})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/totp-step-used",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.MarkTOTPStepUsedProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestMarkTOTPStepUsedProxy_StepFarInFuture_Rejected is F6's own regression:
// a step far beyond the clock-skew window must be refused outright, before
// ever reaching storage — the exact shape that used to let a system.write-only
// caller permanently poison a target's anti-replay counter.
func TestMarkTOTPStepUsedProxy_StepFarInFuture_Rejected(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	require.NoError(t, db.Create(&models.MFASecret{UserID: 1, SecretEnc: []byte("x"), SecretMeta: []byte("y")}).Error)

	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "step": nowTOTPStep(t) + 1_000_000})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/totp-step-used",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.MarkTOTPStepUsedProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code, "a step this far from now must be refused, not persisted")

	secret, err := cs.Storage().GetMFASecret(r.Context(), 1)
	require.NoError(t, err)
	assert.Nil(t, secret.LastUsedStep, "the target's anti-replay counter must be untouched by a rejected step")
}

func TestMarkTOTPStepUsedProxy_StorageError(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "step": nowTOTPStep(t)})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/totp-step-used",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.MarkTOTPStepUsedProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestMarkTOTPStepUsedProxy_NoMatchingRow — no MFASecret row exists for the
// user, so the conditional UPDATE matches zero rows: not an error, "fresh":false.
func TestMarkTOTPStepUsedProxy_NoMatchingRow(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "step": nowTOTPStep(t)})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/totp-step-used",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.MarkTOTPStepUsedProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Fresh bool `json:"fresh"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.False(t, resp.Data.Fresh)
}

// TestMarkTOTPStepUsedProxy_FreshStep — an MFASecret row exists with no prior
// used step, so the conditional UPDATE matches and "fresh":true is returned.
func TestMarkTOTPStepUsedProxy_FreshStep(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	require.NoError(t, db.Create(&models.MFASecret{UserID: 1, SecretEnc: []byte("x"), SecretMeta: []byte("y")}).Error)

	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "step": nowTOTPStep(t)})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/totp-step-used",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.MarkTOTPStepUsedProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Fresh bool `json:"fresh"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.True(t, resp.Data.Fresh)
}

// TestMarkTOTPStepUsedProxy_ReplayedStep — a step at or below the stored
// last-used step matches zero rows (anti-replay guard) — "fresh":false.
func TestMarkTOTPStepUsedProxy_ReplayedStep(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	now := nowTOTPStep(t)
	lastUsed := now
	require.NoError(t, db.Create(&models.MFASecret{UserID: 1, SecretEnc: []byte("x"), SecretMeta: []byte("y"), LastUsedStep: &lastUsed}).Error)

	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "step": now})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/totp-step-used",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.MarkTOTPStepUsedProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Fresh bool `json:"fresh"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.False(t, resp.Data.Fresh)
}
