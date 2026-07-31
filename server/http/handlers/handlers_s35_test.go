// handlers_s35_test.go — broken-DB error-path sweep for users_crud.go,
// rbac.go, and groups_proxy.go handlers whose storage-error 500 branches
// were not yet covered.
package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

var s35DBCounter atomic.Int64

func freshCoreBrokenS35(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := s35DBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_s35_%d?mode=memory&cache=shared", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// ── UserHandler / users_crud.go ───────────────────────────────────────────────

// GetUser: id=0 → core.GetUser returns a validation error ("Validation error:
// user ID is required", no "not found") → 500 (lines 227-228).
func TestGetUser_ZeroID_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewUserHandler(kc)
	require.NoError(t, err)
	r := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/users/0", nil), "id", "0"))
	w := httptest.NewRecorder()
	h.GetUser(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// IssueMFAChallenge: broken DB → storage.CreateMFAChallenge fails → 500
// (lines 469-472).
func TestIssueMFAChallenge_DBError_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewUserHandler(kc)
	require.NoError(t, err)
	r := withUserCtxS7(withChiParamS7(
		httptest.NewRequest(http.MethodPost, "/api/v1/users/1/mfa-challenge", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.IssueMFAChallenge(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// RestoreUser: id=0 → core.RestoreUser returns "Validation error: user ID is
// required" (no "not found") → 500 (lines 746-747).
func TestRestoreUser_ZeroID_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewUserHandler(kc)
	require.NoError(t, err)
	r := withUserCtxS7(withChiParamS7(
		httptest.NewRequest(http.MethodPost, "/api/v1/users/0/restore", nil), "id", "0"))
	w := httptest.NewRecorder()
	h.RestoreUser(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// UnlockUser: id=0 → core.UnlockUser returns "user ID is required" (no "not
// found") → 500 (lines 770-771).
func TestUnlockUser_ZeroID_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewUserHandler(kc)
	require.NoError(t, err)
	r := withUserCtxS7(withChiParamS7(
		httptest.NewRequest(http.MethodPost, "/api/v1/users/0/unlock", nil), "id", "0"))
	w := httptest.NewRecorder()
	h.UnlockUser(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// SuspendUser / accountStateAction: non-numeric id triggers the ParseUint error
// branch → 400 (lines 784-787, 2 stmts).
func TestSuspendUser_BadID_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewUserHandler(kc)
	require.NoError(t, err)
	r := withUserCtxS7(withChiParamS7(
		httptest.NewRequest(http.MethodPost, "/api/v1/users/bad/suspend", nil), "id", "bad"))
	w := httptest.NewRecorder()
	h.SuspendUser(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// SuspendUser / accountStateAction: broken DB → transition returns "Data
// retrieval failed" (no "not found") → 500 (transition-error body).
func TestSuspendUser_DBError_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewUserHandler(kc)
	require.NoError(t, err)
	// id=2 ≠ admin.UserID(1) so the self-suspend guard passes.
	r := withUserCtxS7(withChiParamS7(
		httptest.NewRequest(http.MethodPost, "/api/v1/users/2/suspend", nil), "id", "2"))
	w := httptest.NewRecorder()
	h.SuspendUser(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── RBACHandler / rbac.go ─────────────────────────────────────────────────────

// GetRole: broken DB → GetRoleWithPermissions fails with "Data retrieval failed"
// (no "not found") → 500 (line 238).
func TestGetRole_DBError_S35(t *testing.T) {
	t.Parallel()
	h := NewRBACHandler(freshCoreBrokenS35(t))
	r := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/roles/1", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.GetRole(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// GetRoleByName: broken DB → GetRoleByName fails with "Data retrieval failed"
// (no "not found") → 500 (line 280).
func TestGetRoleByName_DBError_S35(t *testing.T) {
	t.Parallel()
	h := NewRBACHandler(freshCoreBrokenS35(t))
	r := withUserCtxS7(httptest.NewRequest(http.MethodGet, "/api/v1/roles/by-name?name=admin", nil))
	w := httptest.NewRecorder()
	h.GetRoleByName(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// UpdateRole: broken DB → GetRole fails with "Data retrieval failed" → 500
// (line 316).
func TestUpdateRole_DBError_S35(t *testing.T) {
	t.Parallel()
	h := NewRBACHandler(freshCoreBrokenS35(t))
	body := bytes.NewBufferString(`{}`)
	r := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodPut, "/api/v1/roles/1", body), "id", "1"))
	w := httptest.NewRecorder()
	h.UpdateRole(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// DeleteRole: broken DB → GetRole fails with "Data retrieval failed" → 500
// (line 409).
func TestDeleteRole_DBError_S35(t *testing.T) {
	t.Parallel()
	h := NewRBACHandler(freshCoreBrokenS35(t))
	r := withUserCtxS7(withChiParamS7(httptest.NewRequest(http.MethodDelete, "/api/v1/roles/1", nil), "id", "1"))
	w := httptest.NewRecorder()
	h.DeleteRole(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── GroupHandler proxy / groups_proxy.go ─────────────────────────────────────

// CreateGroupProxy: broken DB → CreateGroup fails → 500 (lines 111-115).
func TestCreateGroupProxy_DBError_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewGroupHandler(kc)
	require.NoError(t, err)
	body := bytes.NewBufferString(`{"name":"test-group","description":"test"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/groups", body)
	w := httptest.NewRecorder()
	h.CreateGroupProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// GetGroupProxy: broken DB → GetGroup returns "Data retrieval failed" (not
// "not found") → isGroupNotFound=false → 500 (lines 132-134).
func TestGetGroupProxy_DBError_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewGroupHandler(kc)
	require.NoError(t, err)
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/groups/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetGroupProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// UpdateGroupProxy: broken DB → UpdateGroup fails with "Storage operation
// failed" → isGroupNotFound=false → 500.
func TestUpdateGroupProxy_DBError_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewGroupHandler(kc)
	require.NoError(t, err)
	body := bytes.NewBufferString(`{"name":"updated","description":"test"}`)
	r := withChiParamS7(httptest.NewRequest(http.MethodPut, "/api/v1/system/groups/1", body), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateGroupProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// DeleteGroupProxy: broken DB → DeleteGroup → GetGroup returns "Data retrieval
// failed" → isGroupNotFound=false → 500 (lines 184-186).
func TestDeleteGroupProxy_DBError_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewGroupHandler(kc)
	require.NoError(t, err)
	r := withChiParamS7(httptest.NewRequest(http.MethodDelete, "/api/v1/system/groups/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteGroupProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// RestoreGroupProxy: broken DB → RestoreGroup result.Error → "Storage operation
// failed" → isGroupNotFound=false → 500 (lines 203-205).
func TestRestoreGroupProxy_DBError_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewGroupHandler(kc)
	require.NoError(t, err)
	r := withChiParamS7(
		httptest.NewRequest(http.MethodPost, "/api/v1/system/groups/1/restore", nil), "id", "1")
	w := httptest.NewRecorder()
	h.RestoreGroupProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ListGroupsProxy: broken DB → ListGroups fails → 500.
func TestListGroupsProxy_DBError_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewGroupHandler(kc)
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/groups", nil)
	w := httptest.NewRecorder()
	h.ListGroupsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ListGroupsPageProxy: broken DB → ListGroupsPage fails → 500.
func TestListGroupsPageProxy_DBError_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewGroupHandler(kc)
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/groups/page?offset=0&limit=10", nil)
	w := httptest.NewRecorder()
	h.ListGroupsPageProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// AddGroupMemberProxy: broken DB → AddUserToGroup → GetUser fails with
// "Data retrieval failed" → isGroupNotFound=false → 500.
func TestAddGroupMemberProxy_DBError_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewGroupHandler(kc)
	require.NoError(t, err)
	body := bytes.NewBufferString(`{"user_id":2}`)
	r := withChiParamS7(
		httptest.NewRequest(http.MethodPost, "/api/v1/system/groups/1/members", body), "id", "1")
	w := httptest.NewRecorder()
	h.AddGroupMemberProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// RemoveGroupMemberProxy: broken DB → RemoveUserFromGroup fails → 500.
func TestRemoveGroupMemberProxy_DBError_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewGroupHandler(kc)
	require.NoError(t, err)
	r := withChiParamsMapS7(
		httptest.NewRequest(http.MethodDelete, "/api/v1/system/groups/1/members/2", nil),
		map[string]string{"id": "1", "userId": "2"},
	)
	w := httptest.NewRecorder()
	h.RemoveGroupMemberProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ListGroupMembersProxy: broken DB → ListGroupMembers → GetGroup returns
// "Data retrieval failed" → isGroupNotFound=false → 500.
func TestListGroupMembersProxy_DBError_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewGroupHandler(kc)
	require.NoError(t, err)
	r := withChiParamS7(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/groups/1/members", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListGroupMembersProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ListGroupMembersByIDsProxy: broken DB → ListGroupMembersByGroupIDs fails → 500.
func TestListGroupMembersByIDsProxy_DBError_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewGroupHandler(kc)
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/groups/members-by-ids?ids=1,2", nil)
	w := httptest.NewRecorder()
	h.ListGroupMembersByIDsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// GetUserGroupsProxy: broken DB → GetUserGroups fails → 500.
func TestGetUserGroupsProxy_DBError_S35(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS35(t)
	h, err := NewGroupHandler(kc)
	require.NoError(t, err)
	r := withChiParamS7(
		httptest.NewRequest(http.MethodGet, "/api/v1/system/users/1/groups", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetUserGroupsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
