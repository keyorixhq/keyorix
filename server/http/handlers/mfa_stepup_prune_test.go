// mfa_stepup_prune_test.go — coverage for PruneMFAStepUpGrantsProxy
// (mfa_stepup_proxy.go), previously untested (0% coverage): POST
// /api/v1/system/mfa/stepup-grants/prune.
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

func TestPruneMFAStepUpGrantsProxy_BadJSON(t *testing.T) {
	h, _ := freshCoreWithStepUpGrant(t, time.Now().UTC().Add(10*time.Minute))
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/stepup-grants/prune",
		bytes.NewReader([]byte("{bad json}")))
	w := httptest.NewRecorder()
	h.PruneMFAStepUpGrantsProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPruneMFAStepUpGrantsProxy_MissingBefore(t *testing.T) {
	h, _ := freshCoreWithStepUpGrant(t, time.Now().UTC().Add(10*time.Minute))
	body, _ := json.Marshal(map[string]interface{}{})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/stepup-grants/prune",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.PruneMFAStepUpGrantsProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPruneMFAStepUpGrantsProxy_StorageError(t *testing.T) {
	h, db := freshCoreWithStepUpGrant(t, time.Now().UTC().Add(10*time.Minute))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	body, _ := json.Marshal(map[string]interface{}{"before": time.Now().UTC()})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/stepup-grants/prune",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.PruneMFAStepUpGrantsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestPruneMFAStepUpGrantsProxy_Success — the seeded grant's expiry is far in
// the future, so a "before" cutoff of now (clamped inside
// core.PruneMFAStepUpGrants against the retention window) deletes nothing —
// exercises the 200 success path with deleted:0 without depending on the
// server's default retention window.
func TestPruneMFAStepUpGrantsProxy_Success(t *testing.T) {
	h, _ := freshCoreWithStepUpGrant(t, time.Now().UTC().Add(10*time.Minute))
	body, _ := json.Marshal(map[string]interface{}{"before": time.Now().UTC()})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/mfa/stepup-grants/prune",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.PruneMFAStepUpGrantsProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Deleted int64 `json:"deleted"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.Equal(t, int64(0), resp.Data.Deleted)
}
