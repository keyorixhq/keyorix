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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

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
	body, _ := json.Marshal(map[string]interface{}{"user_id": 0, "step": 5})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/totp-step-used",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.MarkTOTPStepUsedProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestMarkTOTPStepUsedProxy_StorageError(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewAuthHandler(cs, false)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "step": 5})
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
	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "step": 5})
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

	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "step": 5})
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
	lastUsed := int64(10)
	require.NoError(t, db.Create(&models.MFASecret{UserID: 1, SecretEnc: []byte("x"), SecretMeta: []byte("y"), LastUsedStep: &lastUsed}).Error)

	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "step": 5})
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
