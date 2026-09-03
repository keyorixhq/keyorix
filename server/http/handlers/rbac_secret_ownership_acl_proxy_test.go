// rbac_secret_ownership_acl_proxy_test.go — coverage for
// ClearProjectSecretOwnershipProxy and DeleteSecretACLsByUserAndProjectProxy
// (rbac_role_grants_proxy.go), previously untested (0% coverage): both are
// thin passthroughs onto storage.Storage with no in-handler ceiling check
// (authority is enforced by the /system route group's blanket system.write
// gate, not by these handlers themselves — see the file's package doc).
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── ClearProjectSecretOwnershipProxy ────────────────────────────────────────

func TestClearProjectSecretOwnershipProxy_BadJSON(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/rbac/clear-project-secret-ownership",
		bytes.NewReader([]byte("{bad json}")))
	w := httptest.NewRecorder()
	h.ClearProjectSecretOwnershipProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClearProjectSecretOwnershipProxy_MissingFields(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	body, _ := json.Marshal(map[string]interface{}{"user_id": 0, "project_id": 1})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/rbac/clear-project-secret-ownership",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ClearProjectSecretOwnershipProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestClearProjectSecretOwnershipProxy_StorageError(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "project_id": 1})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/rbac/clear-project-secret-ownership",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ClearProjectSecretOwnershipProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestClearProjectSecretOwnershipProxy_Success(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "project_id": 1})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/rbac/clear-project-secret-ownership",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ClearProjectSecretOwnershipProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Cleared bool `json:"cleared"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.True(t, resp.Data.Cleared)
}

// ── DeleteSecretACLsByUserAndProjectProxy ───────────────────────────────────

func TestDeleteSecretACLsByUserAndProjectProxy_BadJSON(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/rbac/delete-secret-acls-by-user-and-project",
		bytes.NewReader([]byte("{bad json}")))
	w := httptest.NewRecorder()
	h.DeleteSecretACLsByUserAndProjectProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteSecretACLsByUserAndProjectProxy_MissingFields(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "project_id": 0})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/rbac/delete-secret-acls-by-user-and-project",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.DeleteSecretACLsByUserAndProjectProxy(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeleteSecretACLsByUserAndProjectProxy_StorageError(t *testing.T) {
	cs, db := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "project_id": 1})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/rbac/delete-secret-acls-by-user-and-project",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.DeleteSecretACLsByUserAndProjectProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteSecretACLsByUserAndProjectProxy_Success(t *testing.T) {
	cs, _ := freshCoreS12WithAdmin(t)
	h := NewRBACHandler(cs)
	body, _ := json.Marshal(map[string]interface{}{"user_id": 1, "project_id": 1})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/rbac/delete-secret-acls-by-user-and-project",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.DeleteSecretACLsByUserAndProjectProxy(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Deleted bool `json:"deleted"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.True(t, resp.Data.Deleted)
}
