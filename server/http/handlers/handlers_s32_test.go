// handlers_s32_test.go — broken-DB error-path sweep for remaining proxy endpoints
// not covered in s30/s31 (secret-dependencies, shares-by-owner/user,
// user-with-role-grants, project-members, user-memberships, group-role-grants,
// anomaly-alert purge, risk-exceptions, invitations).
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

var s32DBCounter atomic.Int64

func freshCoreBrokenS32(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := s32DBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_s32_%d?mode=memory&cache=shared", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// ── SecretHandler / secret_dependencies_proxy.go ──────────────────────────────

func TestListSecretDependenciesForProjectProxy_DBError_S32(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS32(t)
	h, err := NewSecretHandler(kc)
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/secret-dependencies?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListSecretDependenciesForProjectProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListSecretDependenciesForProjectForUpdateProxy_DBError_S32(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS32(t)
	h, err := NewSecretHandler(kc)
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/secret-dependencies/for-update?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListSecretDependenciesForProjectForUpdateProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetSecretIncludingDeletedProxy_DBError_S32(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS32(t)
	h, err := NewSecretHandler(kc)
	require.NoError(t, err)
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/secrets/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetSecretIncludingDeletedProxy(w, r)
	// local GetSecretIncludingDeleted wraps First() errors as "not found" → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── ShareHandler / misc_remote_proxy.go ───────────────────────────────────────

func TestListSharesByOwnerProxy_DBError_S32(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS32(t)
	h, err := NewShareHandler(kc)
	require.NoError(t, err)
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/shares/by-owner/1", nil), "ownerID", "1")
	w := httptest.NewRecorder()
	h.ListSharesByOwnerProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListSharesByUserProxy_DBError_S32(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS32(t)
	h, err := NewShareHandler(kc)
	require.NoError(t, err)
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/shares/by-user/1", nil), "userID", "1")
	w := httptest.NewRecorder()
	h.ListSharesByUserProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── UserHandler / misc_remote_proxy.go ────────────────────────────────────────

func TestCreateUserWithRoleGrantsProxy_DBError_S32(t *testing.T) {
	t.Parallel()
	kc := freshCoreBrokenS32(t)
	h, err := NewUserHandler(kc)
	require.NoError(t, err)
	body := bytes.NewBufferString(`{"username":"alice","email":"alice@example.com","password_hash":"$2a$10$abc","is_active":true,"account_state":"active","grants":[]}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/users/with-role-grants", body)
	w := httptest.NewRecorder()
	h.CreateUserWithRoleGrantsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── CatalogHandler / project_catalog_proxy.go ─────────────────────────────────

func TestListProjectMembersProxy_DBError_S32(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS32(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/projects/1/members", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListProjectMembersProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── CatalogHandler / project_memberships_proxy.go ─────────────────────────────

func TestListUserMembershipsProxy_DBError_S32(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS32(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/project-memberships/by-user/1", nil), "userID", "1")
	w := httptest.NewRecorder()
	h.ListUserMembershipsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCountMembershipsByUsersProxy_DBError_S32(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS32(t))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/project-memberships/counts?user_ids=1,2,3", nil)
	w := httptest.NewRecorder()
	h.CountMembershipsByUsersProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── CatalogHandler / invitations_proxy.go ─────────────────────────────────────

func TestGetInvitationProxy_DBError_S32(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreBrokenS32(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/invitations/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetInvitationProxy(w, r)
	// GetProjectInvitation wraps First() errors as "ErrorNotFound" → 404
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── RBACHandler / rbac_role_grants_proxy.go ───────────────────────────────────

func TestGetGroupRoleGrantsProxy_DBError_S32(t *testing.T) {
	t.Parallel()
	h := NewRBACHandler(freshCoreBrokenS32(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/rbac/groups/1/role-grants", nil), "groupID", "1")
	w := httptest.NewRecorder()
	h.GetGroupRoleGrantsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListGroupRoleAssignmentsProxy_DBError_S32(t *testing.T) {
	t.Parallel()
	h := NewRBACHandler(freshCoreBrokenS32(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/rbac/groups/1/role-assignments", nil), "groupID", "1")
	w := httptest.NewRecorder()
	h.ListGroupRoleAssignmentsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── AuditHandler / retention_proxy.go ─────────────────────────────────────────

func TestDeleteAnomalyAlertsBeforeProxy_DBError_S32(t *testing.T) {
	t.Parallel()
	h := NewAuditHandler(freshCoreBrokenS32(t))
	body := bytes.NewBufferString(`{"ack_before":"2020-01-01T00:00:00Z","unack_ceiling":"2020-06-01T00:00:00Z"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/system/retention/anomaly-alerts/purge", body)
	w := httptest.NewRecorder()
	h.DeleteAnomalyAlertsBeforeProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── DashboardHandler / risk_exceptions_proxy.go ───────────────────────────────

func TestGetRiskExceptionProxy_DBError_S32(t *testing.T) {
	t.Parallel()
	h := NewDashboardHandler(freshCoreBrokenS32(t))
	r := withChiParamS7(httptest.NewRequest(http.MethodGet, "/api/v1/system/risk-exceptions/1", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetRiskExceptionProxy(w, r)
	// local GetRiskException correctly separates ErrRecordNotFound from other errors
	// → broken DB returns generic "retrieval failed" error → 500
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestListRiskExceptionsProxy_DBError_S32(t *testing.T) {
	t.Parallel()
	h := NewDashboardHandler(freshCoreBrokenS32(t))
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/risk-exceptions", nil)
	w := httptest.NewRecorder()
	h.ListRiskExceptionsProxy(w, r)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
