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
func TestCreateGroupProxy_DBError_S35(t *testing.T) {
	t.Parallel()

	// Companion baseline: the IDENTICAL request minus the trigger must
	// succeed -- isolates the 500 below to the trigger, not the new
	// authority check or another storage bug. clientSafe() redacts the
	// response body to a fixed generic string, so this before/after delta
	// is the available proof.
	baselineCS, _ := freshCoreS12WithAdmin(t)
	baselineH, err := NewGroupHandler(baselineCS)
	require.NoError(t, err)
	baselineBody := bytes.NewBufferString(`{"name":"test-group-baseline","description":"test"}`)
	baselineR := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/system/groups", baselineBody))
	baselineW := httptest.NewRecorder()
	baselineH.CreateGroupProxy(baselineW, baselineR)
	require.Equal(t, http.StatusOK, baselineW.Code, "baseline (no trigger) must succeed: %s", baselineW.Body.String())

	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	require.NoError(t, db.Exec(`
		CREATE TRIGGER block_groups_insert
		BEFORE INSERT ON groups
		BEGIN
			SELECT RAISE(ABORT, 'simulated write failure: disk quota exceeded on host db-07.internal');
		END;
	`).Error)
	body := bytes.NewBufferString(`{"name":"test-group","description":"test"}`)
	r := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/system/groups", body))
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

// UpdateGroupProxy: storage error → UpdateGroup fails with "Storage operation
// failed" → isGroupNotFound=false → 500. See TestCreateGroupProxy_DBError_S35
// for why this uses an admin-seeded working DB with a real group row and an
// UPDATE-blocking trigger on "groups", rather than freshCoreBrokenS35's
// fully-closed connection or an outright DROP TABLE (both fail the new
// caller-authority check itself, before ever reaching the group storage call
// this test means to exercise) -- the trigger leaves UpdateGroup's own
// GetGroup lookup (a SELECT) and the authority check intact, and aborts only
// the subsequent UPDATE.
func TestUpdateGroupProxy_DBError_S35(t *testing.T) {
	t.Parallel()

	// Companion baseline: the IDENTICAL request/fixture shape minus the
	// trigger must succeed -- isolates the 500 below to the trigger, not
	// the new authority check or another storage bug. clientSafe() redacts
	// the response body to a fixed generic string, so this before/after
	// delta is the available proof.
	baselineCS, baselineDB := freshCoreS12WithAdmin(t)
	baselineH, err := NewGroupHandler(baselineCS)
	require.NoError(t, err)
	baselineGrp := &models.Group{Name: "s35-update-baseline", NameFolded: "s35-update-baseline"}
	require.NoError(t, baselineDB.Create(baselineGrp).Error)
	baselineBody := bytes.NewBufferString(`{"name":"updated","description":"test"}`)
	baselineR := withUserCtx(withChiParamS7(httptest.NewRequest(http.MethodPut, "/api/v1/system/groups/1", baselineBody), "id", fmt.Sprintf("%d", baselineGrp.ID)))
	baselineW := httptest.NewRecorder()
	baselineH.UpdateGroupProxy(baselineW, baselineR)
	require.Equal(t, http.StatusOK, baselineW.Code, "baseline (no trigger) must succeed: %s", baselineW.Body.String())

	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	grp := &models.Group{Name: "s35-update-dberror", NameFolded: "s35-update-dberror"}
	require.NoError(t, db.Create(grp).Error)
	require.NoError(t, db.Exec(`
		CREATE TRIGGER block_groups_update
		BEFORE UPDATE ON groups
		BEGIN
			SELECT RAISE(ABORT, 'simulated write failure: disk quota exceeded on host db-07.internal');
		END;
	`).Error)
	body := bytes.NewBufferString(`{"name":"updated","description":"test"}`)
	r := withUserCtx(withChiParamS7(httptest.NewRequest(http.MethodPut, "/api/v1/system/groups/1", body), "id", fmt.Sprintf("%d", grp.ID)))
	w := httptest.NewRecorder()
	h.UpdateGroupProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// DeleteGroupProxy: storage error → DeleteGroup's soft-delete (an UPDATE)
// fails → isGroupNotFound=false → 500 (lines 184-186). See
// TestCreateGroupProxy_DBError_S35 for why this uses an admin-seeded working
// DB with a real group row and an UPDATE-blocking trigger on "groups" --
// DeleteGroup's own preceding GetGroup lookup (a SELECT) and the authority
// check both stay intact, so only the soft-delete UPDATE aborts.
func TestDeleteGroupProxy_DBError_S35(t *testing.T) {
	t.Parallel()

	// Companion baseline: the IDENTICAL request/fixture shape minus the
	// trigger must succeed -- isolates the 500 below to the trigger, not
	// the new authority check or another storage bug. clientSafe() redacts
	// the response body to a fixed generic string, so this before/after
	// delta is the available proof.
	baselineCS, baselineDB := freshCoreS12WithAdmin(t)
	baselineH, err := NewGroupHandler(baselineCS)
	require.NoError(t, err)
	baselineGrp := &models.Group{Name: "s35-delete-baseline", NameFolded: "s35-delete-baseline"}
	require.NoError(t, baselineDB.Create(baselineGrp).Error)
	baselineR := withUserCtx(withChiParamS7(httptest.NewRequest(http.MethodDelete, "/api/v1/system/groups/1", nil), "id", fmt.Sprintf("%d", baselineGrp.ID)))
	baselineW := httptest.NewRecorder()
	baselineH.DeleteGroupProxy(baselineW, baselineR)
	require.Equal(t, http.StatusOK, baselineW.Code, "baseline (no trigger) must succeed: %s", baselineW.Body.String())

	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	grp := &models.Group{Name: "s35-delete-dberror", NameFolded: "s35-delete-dberror"}
	require.NoError(t, db.Create(grp).Error)
	require.NoError(t, db.Exec(`
		CREATE TRIGGER block_groups_update_delete
		BEFORE UPDATE ON groups
		BEGIN
			SELECT RAISE(ABORT, 'simulated write failure: disk quota exceeded on host db-07.internal');
		END;
	`).Error)
	r := withUserCtx(withChiParamS7(httptest.NewRequest(http.MethodDelete, "/api/v1/system/groups/1", nil), "id", fmt.Sprintf("%d", grp.ID)))
	w := httptest.NewRecorder()
	h.DeleteGroupProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

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
func TestRestoreGroupProxy_DBError_S35(t *testing.T) {
	t.Parallel()

	// Companion baseline: the IDENTICAL request/fixture shape (a genuinely
	// soft-deleted group) minus the trigger must succeed -- isolates the
	// 500 below to the trigger, not the new roles.assign authority check
	// or another storage bug. clientSafe() redacts the response body to a
	// fixed generic string, so this before/after delta is the available
	// proof.
	baselineCS, baselineDB := freshCoreS12WithAdmin(t)
	baselineH, err := NewGroupHandler(baselineCS)
	require.NoError(t, err)
	baselineGrp := &models.Group{Name: "s35-restore-baseline", NameFolded: "s35-restore-baseline"}
	require.NoError(t, baselineDB.Create(baselineGrp).Error)
	require.NoError(t, baselineDB.Delete(baselineGrp).Error)
	baselineR := withUserCtx(withChiParamS7(
		httptest.NewRequest(http.MethodPost, "/api/v1/system/groups/1/restore", nil), "id", fmt.Sprintf("%d", baselineGrp.ID)))
	baselineW := httptest.NewRecorder()
	baselineH.RestoreGroupProxy(baselineW, baselineR)
	require.Equal(t, http.StatusOK, baselineW.Code, "baseline (no trigger) must succeed: %s", baselineW.Body.String())

	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	grp := &models.Group{Name: "s35-restore-dberror", NameFolded: "s35-restore-dberror"}
	require.NoError(t, db.Create(grp).Error)
	require.NoError(t, db.Delete(grp).Error) // soft-delete, so RestoreGroup's UPDATE matches a row
	require.NoError(t, db.Exec(`
		CREATE TRIGGER block_groups_update_restore
		BEFORE UPDATE ON groups
		BEGIN
			SELECT RAISE(ABORT, 'simulated write failure: disk quota exceeded on host db-07.internal');
		END;
	`).Error)
	r := withUserCtx(withChiParamS7(
		httptest.NewRequest(http.MethodPost, "/api/v1/system/groups/1/restore", nil), "id", fmt.Sprintf("%d", grp.ID)))
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
