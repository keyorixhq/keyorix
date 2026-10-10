// handlers_s30_test.go — error-path coverage sweep using a closed DB.
//
// Every handler function that was missing its "coreService returned an error"
// branch is tested here by constructing a KeyorixCore backed by a SQLite DB
// whose underlying sql.DB has already been closed. Any storage call then
// immediately returns an error, driving the handler's error-response branch.
package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
)

// freshCoreBrokenS30 creates a KeyorixCore backed by a closed SQLite DB so
// that every storage call returns an error immediately.
func freshCoreBrokenS30(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := sqlitetest.Open(t, "kxhandlers_s30_")
	// Minimal migration so the DB file is valid, then close.
	require.NoError(t, db.AutoMigrate(&models.Project{}))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	return core.NewKeyorixCore(store.NewLocalStorage(db))
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

// ── DashboardHandler ──────────────────────────────────────────────────────────

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

// ── UserHandler ───────────────────────────────────────────────────────────────
