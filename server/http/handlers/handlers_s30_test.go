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

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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

func TestUpdateProjectProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	body := bytes.NewBufferString(`{"name":"x"}`)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", body), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateProjectProxy(w, req)
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

func TestCreateBreakGlassActivationProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	body := bytes.NewBufferString(`{"project_id":1,"user_id":1,"state":"active","activated_by":1}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	w := httptest.NewRecorder()
	h.CreateBreakGlassActivationProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCreateMembershipProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	body := bytes.NewBufferString(`{"project_id":1,"user_id":1,"role":"admin","state":"active"}`)
	req := httptest.NewRequest(http.MethodPost, "/", body)
	w := httptest.NewRecorder()
	h.CreateMembershipProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteClosedAccessReviewsBeforeProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := httptest.NewRequest(http.MethodPost, "/", retentionBody())
	w := httptest.NewRecorder()
	h.DeleteClosedAccessReviewsBeforeProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteExpiredBreakGlassBeforeProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := httptest.NewRequest(http.MethodPost, "/", retentionBody())
	w := httptest.NewRecorder()
	h.DeleteExpiredBreakGlassBeforeProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDeleteResolvedAccessRequestsBeforeProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := httptest.NewRequest(http.MethodPost, "/", retentionBody())
	w := httptest.NewRecorder()
	h.DeleteResolvedAccessRequestsBeforeProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestPurgeDeletedProjectsBeforeProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := httptest.NewRequest(http.MethodPost, "/", retentionBody())
	w := httptest.NewRecorder()
	h.PurgeDeletedProjectsBeforeProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestPurgeDeletedEnvironmentsBeforeProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS30(t))
	req := httptest.NewRequest(http.MethodPost, "/", retentionBody())
	w := httptest.NewRecorder()
	h.PurgeDeletedEnvironmentsBeforeProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── AuthHandler ───────────────────────────────────────────────────────────────

func TestDeleteConnectRefGrantProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewAuthHandler(freshCoreBrokenS30(t), false)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.DeleteConnectRefGrantProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
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

func TestListGlobalAdminAssignmentsForUpdateProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h := NewRBACHandler(freshCoreBrokenS30(t))
	// role_ids=1 forces the storage call; empty role_ids short-circuits with nil,nil
	req := httptest.NewRequest(http.MethodGet, "/?role_ids=1", nil)
	w := httptest.NewRecorder()
	h.ListGlobalAdminAssignmentsForUpdateProxy(w, req)
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

func TestPurgeDeletedSecretsBeforeProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h, err := NewSecretHandler(freshCoreBrokenS30(t))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", retentionBody())
	w := httptest.NewRecorder()
	h.PurgeDeletedSecretsBeforeProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

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

func TestUpdateGroupProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h, err := NewGroupHandler(freshCoreBrokenS30(t))
	require.NoError(t, err)
	body := bytes.NewBufferString(`{"name":"x"}`)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", body), "id", "1")
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

func TestPurgeDeletedUsersBeforeProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h, err := NewUserHandler(freshCoreBrokenS30(t))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/", retentionBody())
	w := httptest.NewRecorder()
	h.PurgeDeletedUsersBeforeProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListUsersInStateBeforeProxy_DBError_S30(t *testing.T) {
	t.Parallel()
	h, err := NewUserHandler(freshCoreBrokenS30(t))
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/?state=pending&before=2020-01-01T00:00:00Z", nil)
	w := httptest.NewRecorder()
	h.ListUsersInStateBeforeProxy(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
