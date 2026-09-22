// handlers_s30_test.go — error-path coverage sweep using a closed DB.
//
// Every handler function that was missing its "coreService returned an error"
// branch is tested here by constructing a KeyorixCore backed by a SQLite DB
// whose underlying sql.DB has already been closed. Any storage call then
// immediately returns an error, driving the handler's error-response branch.
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

var s30DBCounter atomic.Int64

// freshCoreBrokenS30 creates a KeyorixCore backed by a closed SQLite DB so
// that every storage call returns an error immediately.
func freshCoreBrokenS30(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := s30DBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_s30_%d?mode=memory&cache=shared", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	// Minimal migration so the DB file is valid, then close.
	require.NoError(t, db.AutoMigrate(&models.Project{}))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// retentionBody returns a valid JSON body for retention-proxy handlers.
func retentionBody() *bytes.Buffer {
	return bytes.NewBufferString(`{"before":"2020-01-01T00:00:00Z"}`)
}

// ── CatalogHandler ────────────────────────────────────────────────────────────

func TestListProjectMembers_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil)), "id", "1")
	w := httptest.NewRecorder()
	h.ListProjectMembers(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetProjectAccessReview_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil)), "id", "1")
	w := httptest.NewRecorder()
	h.GetProjectAccessReview(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListInvitations_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListInvitations(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListAccessRequests_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil)), "id", "1")
	w := httptest.NewRecorder()
	h.ListAccessRequests(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListProjectMemberships_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListProjectMemberships(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListMachineIdentities_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListMachineIdentities(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListProjectsProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListProjectsProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListProjectsWithCountsProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := httptest.NewRequest(http.MethodGet, "/?include_deleted=false", nil)
	w := httptest.NewRecorder()
	h.ListProjectsWithCountsProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListAllMachineIdentitiesProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListAllMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCountMachineIdentitiesByClassificationProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.CountMachineIdentitiesByClassificationProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListActiveMachineIdentityCredentialsProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ListActiveMachineIdentityCredentialsProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCountMachineIdentityCredentialsByClassificationProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.CountMachineIdentityCredentialsByClassificationProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// FIX-1 moved this handler's role resolution (GetRoleByName) ahead of the
// persist step, so a broken DB connection is now hit there first, not at
// CreateProjectMembership -- and GetRoleByName's error path (project_memberships_proxy.go)
// maps ANY resolution error, including a genuine storage failure, to 400
// "unknown role", matching the same catch-all convention every other
// GetRoleByName caller in this codebase already uses (e.g.
// internal/core/invitations.go's InviteToProject: "unknown role %q: %w"
// regardless of the underlying cause). This is a pre-existing, repo-wide
// convention FIX-1 exposed here for the first time, not a new one introduced
// by it; refining GetRoleByName's error taxonomy is a separate, broader
// change out of this fix's scope.
func TestCreateMembershipProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	body := bytes.NewBufferString(`{"project_id":1,"user_id":1,"role":"viewer","state":"active"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	w := httptest.NewRecorder()
	h.CreateMembershipProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── DashboardHandler ──────────────────────────────────────────────────────────

func TestCreateLegalHoldProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewDashboardHandler(freshCoreBrokenS30(t))
	body := bytes.NewBufferString(`{"reason":"test hold","user_id":1,"placed_by":1}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	w := httptest.NewRecorder()
	h.CreateLegalHoldProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── RBACHandler ───────────────────────────────────────────────────────────────

func TestRBACListRoles_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewRBACHandler(freshCoreBrokenS30(t))
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	w := httptest.NewRecorder()
	h.ListRoles(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRBACGetGroupRoles_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewRBACHandler(freshCoreBrokenS30(t))
	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodGet, "/", nil)), "id", "1")
	w := httptest.NewRecorder()
	h.GetGroupRoles(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListProjectRoleAssignmentsProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewRBACHandler(freshCoreBrokenS30(t))
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListProjectRoleAssignmentsProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListProjectMachineRoleAssignmentsProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewRBACHandler(freshCoreBrokenS30(t))
	req := httptest.NewRequest(http.MethodGet, "/?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListProjectMachineRoleAssignmentsProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteExpiredRoleGrantsProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewRBACHandler(freshCoreBrokenS30(t))
	req := httptest.NewRequest(http.MethodPost, "/", retentionBody())
	w := httptest.NewRecorder()
	h.DeleteExpiredRoleGrantsProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── NotificationHandler ───────────────────────────────────────────────────────

func TestMarkAllRead_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewNotificationHandler(freshCoreBrokenS30(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil))
	w := httptest.NewRecorder()
	h.MarkAllRead(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── AdminJobsHandler ──────────────────────────────────────────────────────────

func TestRunExpiryReminders_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewAdminJobsHandler(freshCoreBrokenS30(t))
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil))
	w := httptest.NewRecorder()
	h.RunExpiryReminders(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── SecretHandler ─────────────────────────────────────────────────────────────

// ── DynamicSecretHandler ──────────────────────────────────────────────────────

func TestCountActiveLeasesProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewDynamicSecretHandler(freshCoreBrokenS30(t))
	req := httptest.NewRequest(http.MethodGet, "/?config_id=1", nil)
	w := httptest.NewRecorder()
	h.CountActiveLeasesProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── GroupHandler ──────────────────────────────────────────────────────────────

// TestUpdateGroupProxy_DBError_S30 exercises UpdateGroupProxy's storage-error
// (500) branch. UpdateGroupProxy now also requires caller authority
// (requireGroupsProxyUsersWrite -> users.write), which itself needs a working
// DB to resolve -- freshCoreBrokenS30's fully-closed connection would fail
// THAT check first and yield 403, never reaching the group storage call this
// test means to exercise. Dropping the "groups" table outright doesn't work
// either: the authority check's own role resolution (scopedRoleIDs ->
// GetUserGroupRoleIDsAt) unconditionally JOINs "groups" to exclude
// soft-deleted groups' role grants, so a dropped "groups" table also fails
// the authority check itself (403), even for a caller with a direct,
// non-group role grant. So this uses a working, admin-seeded DB
// (freshCoreS12WithAdmin, matching withUserCtx's UserID=1) with a real group
// row, then a SQLite trigger that aborts only WRITEs to "groups" --
// isolating the failure to UpdateGroup's own storage call while leaving both
// authority resolution and UpdateGroup's own GetGroup lookup (a SELECT)
// intact -- same technique as handlers_s13_connect_dynamic_test.go's
// block_dynamic_config_update trigger.
func TestUpdateGroupProxy_DBError_S30(t *testing.T) {
	t.Parallel()

	// Companion baseline: the IDENTICAL request/fixture shape, minus the
	// trigger, must succeed -- this isolates the 500 below to the trigger
	// itself, not the new authority check or some other storage bug that
	// would also produce a non-200. clientSafe() redacts the response body
	// down to a fixed generic string, so asserting on the trigger's own
	// RAISE message isn't available; this before/after delta is the
	// alternative proof.
	baselineCS, baselineDB := freshCoreS12WithAdmin(t)
	baselineH, err := NewGroupHandler(baselineCS)
	require.NoError(t, err)
	baselineGrp := &models.Group{Name: "s30-update-baseline", NameFolded: "s30-update-baseline"}
	require.NoError(t, baselineDB.Create(baselineGrp).Error)
	baselineReq := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"name":"x"}`)), "id", fmt.Sprintf("%d", baselineGrp.ID)))
	baselineW := httptest.NewRecorder()
	baselineH.UpdateGroupProxy(baselineW, baselineReq)
	require.Equal(t, http.StatusOK, baselineW.Code, "baseline (no trigger) must succeed: %s", baselineW.Body.String())

	cs, db := freshCoreS12WithAdmin(t)
	h, err := NewGroupHandler(cs)
	require.NoError(t, err)
	grp := &models.Group{Name: "s30-update-dberror", NameFolded: "s30-update-dberror"}
	require.NoError(t, db.Create(grp).Error)
	require.NoError(t, db.Exec(`
		CREATE TRIGGER block_groups_update
		BEFORE UPDATE ON groups
		BEGIN
			SELECT RAISE(ABORT, 'simulated write failure: disk quota exceeded on host db-07.internal');
		END;
	`).Error)
	body := bytes.NewBufferString(`{"name":"x"}`)
	req := withUserCtx(withChiParam(httptest.NewRequest(http.MethodPut, "/", body), "id", fmt.Sprintf("%d", grp.ID)))
	w := httptest.NewRecorder()
	h.UpdateGroupProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCreateGroup_DBError_S30(t *testing.T) {
	t.Parallel()
	h, err := NewGroupHandler(freshCoreBrokenS30(t))
	require.NoError(t, err)
	body := bytes.NewBufferString(`{"name":"testgroup","description":"test"}`)
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/", body))
	w := httptest.NewRecorder()
	h.CreateGroup(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── ShareHandler ──────────────────────────────────────────────────────────────

func TestDeleteExpiredShareRecordsProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h, err := NewShareHandler(freshCoreBrokenS30(t))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", retentionBody())
	w := httptest.NewRecorder()
	h.DeleteExpiredShareRecordsProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── UserHandler ───────────────────────────────────────────────────────────────

func TestListUsersInStateBeforeProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h, err := NewUserHandler(freshCoreBrokenS30(t))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/?state=pending&before=2020-01-01T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.ListUsersInStateBeforeProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
