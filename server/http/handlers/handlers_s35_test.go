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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
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

// CreateGroupProxy: storage error → CreateGroup fails → 500 (lines 111-115).
// CreateGroupProxy now also requires caller authority
// (requireGroupsProxyUsersWrite -> users.write), which needs a working DB to
// resolve -- freshCoreBrokenS35's fully-closed connection would fail THAT
// check first and yield 403, never reaching the group storage call this test
// means to exercise. Dropping the "groups" table outright doesn't work
// either: the authority check's own role resolution (scopedRoleIDs ->
// GetUserGroupRoleIDsAt) unconditionally JOINs "groups" to exclude
// soft-deleted groups' role grants, so a dropped "groups" table also fails
// the authority check itself (403), even for a caller with a direct,
// non-group role grant. So this uses a working, admin-seeded DB
// (freshCoreS12WithAdmin, matching withUserCtx's UserID=1) with a SQLite
// trigger that aborts only WRITEs to "groups" -- isolating the failure to
// CreateGroup's own storage call while leaving authority resolution intact --
// same technique as handlers_s13_connect_dynamic_test.go's
// block_dynamic_config_update trigger.

// GetGroupProxy: broken DB → GetGroup returns "Data retrieval failed" (not
// "not found") → isGroupNotFound=false → 500 (lines 132-134).

// UpdateGroupProxy: storage error → UpdateGroup fails with "Storage operation
// failed" → isGroupNotFound=false → 500. See TestCreateGroupProxy_DBError_S35
// for why this uses an admin-seeded working DB with a real group row and an
// UPDATE-blocking trigger on "groups", rather than freshCoreBrokenS35's
// fully-closed connection or an outright DROP TABLE (both fail the new
// caller-authority check itself, before ever reaching the group storage call
// this test means to exercise) -- the trigger leaves UpdateGroup's own
// GetGroup lookup (a SELECT) and the authority check intact, and aborts only
// the subsequent UPDATE.

// DeleteGroupProxy: storage error → DeleteGroup's soft-delete (an UPDATE)
// fails → isGroupNotFound=false → 500 (lines 184-186). See
// TestCreateGroupProxy_DBError_S35 for why this uses an admin-seeded working
// DB with a real group row and an UPDATE-blocking trigger on "groups" --
// DeleteGroup's own preceding GetGroup lookup (a SELECT) and the authority
// check both stay intact, so only the soft-delete UPDATE aborts.

// RestoreGroupProxy: storage error → RestoreGroup result.Error → "Storage
// operation failed" → isGroupNotFound=false → 500 (lines 203-205). See
// TestCreateGroupProxy_DBError_S35 for why an outright DROP TABLE doesn't
// work here (it also fails the new roles.assign authority check itself,
// yielding 403, not 500) -- this uses an admin-seeded working DB
// (freshCoreS12WithAdmin) with a group that is genuinely soft-deleted (so
// RestoreGroup's `WHERE id = ? AND deleted_at IS NOT NULL` UPDATE actually
// matches a row and the BEFORE UPDATE trigger fires -- a trigger never
// fires for an UPDATE that matches zero rows, which would instead produce
// RestoreGroup's separate "group not found or not deleted" 404). GetGroupRoles
// (group_roles table, empty for this group) and the
// requireGlobalAdminToReinstateAdminRoles authority check both still
// succeed against the intact schema; only the final storage.RestoreGroup
// UPDATE aborts.

// ListGroupsProxy: broken DB → ListGroups fails → 500.

// ListGroupsPageProxy: broken DB → ListGroupsPage fails → 500.

// AddGroupMemberProxy: broken DB → AddUserToGroup → GetUser fails with
// "Data retrieval failed" → isGroupNotFound=false → 500.
// AddGroupMemberProxy: DB write to user_groups fails → 500. freshCoreBrokenS35
// (whole-storage-broken) no longer isolates this -- F6 sweep (2026-09-22)
// added a roles.assign authority check that itself needs to READ storage
// (GetUserRoleIDsAt/GetUserGroupRoleIDsAt) before the write is ever attempted,
// so a fully-broken core now 403s there instead of reaching the write at all.
// Mirrors TestRestoreGroupProxy_DBError_S35's SQL-trigger isolation: a
// working admin-backed core with a trigger that blocks ONLY the targeted
// INSERT, so the 500 is proven to come from THIS write, not the new check.

// RemoveGroupMemberProxy: DB delete on user_groups fails → 500. Same
// isolation rationale and pattern as TestAddGroupMemberProxy_DBError_S35
// above -- a working admin-backed core with a real membership row and a
// trigger blocking only the targeted DELETE.

// ListGroupMembersProxy: broken DB → ListGroupMembers → GetGroup returns
// "Data retrieval failed" → isGroupNotFound=false → 500.

// ListGroupMembersByIDsProxy: broken DB → ListGroupMembersByGroupIDs fails → 500.

// GetUserGroupsProxy: broken DB → GetUserGroups fails → 500.
