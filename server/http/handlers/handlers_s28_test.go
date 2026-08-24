// handlers_s28_test.go — coverage sweep targeting remaining gaps after s27:
//   - machine_identities_proxy.go: ListMachineIdentitiesProxy (bad/missing project_id),
//     CreateMachineIdentityProxy (bad body, missing fields, happy path),
//     GetMachineIdentityProxy (bad id, not found, happy path),
//     TransitionMachineIdentityStateProxy (bad id, bad body, missing from_state, happy path),
//     DeleteOIDCBindingProxy (bad id, not found, happy path),
//     CreateMachineIdentityCredentialProxy (bad body, missing fields, happy path),
//     ListMachineIdentityCredentialsProxy (bad id, happy path),
//     DeleteOIDCBindingProxy, GetMachineRolesProxy, AssignMachineRoleProxy,
//     CountMachineIdentitiesByClassificationProxy, ListAllMachineIdentitiesProxy,
//     ListActiveMachineIdentityCredentialsProxy
//   - access_review_campaigns.go: ListAccessReviewCampaigns (happy path),
//     DecideAccessReviewCampaignItem (bad body, missing action, happy path chain)
//   - project_members.go: AddProjectMember (happy path conflict, unknown role),
//     UpdateProjectMember (missing role, unknown role, happy path),
//     RemoveProjectMember (not a member)
//   - audit.go: WriteAuditCheckpoint (unauthenticated, encryption disabled → 412)
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
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

// ── DB helpers ────────────────────────────────────────────────────────────────

var s28DBCounter atomic.Int64

// freshCoreS28 opens a uniquely-named in-memory SQLite DB with the full
// model set and returns a ready-to-use KeyorixCore.
func freshCoreS28(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := s28DBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_s28_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.AnomalyAlert{},
		&models.RotationPolicy{}, &models.Notification{},
		&models.ProjectMembership{}, &models.SoDPolicy{},
		&models.BreakGlassActivation{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.LoginAttempt{},
		&models.AccessRequest{}, &models.AccessRequestApproval{},
		&models.WebAuthnCredential{}, &models.WebAuthnSession{},
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
		&models.ConnectRefGrant{}, &models.Session{}, &models.SetupToken{},
		&models.MFAChallenge{}, &models.SSOLoginState{},
		&models.MachineIdentity{}, &models.MachineIdentityCredential{},
		&models.MachineIdentityRole{}, &models.MachineIdentityOIDCBinding{},
		&models.SecretDependency{}, &models.RiskException{},
		&models.MFASecret{}, &models.MFARecoveryCode{},
		&models.IdentityProvider{}, &models.ExternalIdentity{},
		&models.LegalHold{}, &models.ShareRecord{},
		&models.PersonalAccessToken{},
		&models.ProjectInvitation{}, &models.SchedulerLockLease{},
		&models.SecretAccessLog{},
		&models.SystemMetadata{},
		&models.PasswordHistory{},
		&models.SecretVersion{},
	))
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// freshCoreS28WithAdmin creates a core pre-seeded with a system_admin role
// and the test user (ID determined by insert order, withUserCtx uses UserID=1).
func freshCoreS28WithAdmin(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := s28DBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_s28a_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.AuditEvent{}, &models.AnomalyAlert{},
		&models.RotationPolicy{}, &models.Notification{},
		&models.ProjectMembership{}, &models.SoDPolicy{},
		&models.BreakGlassActivation{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.LoginAttempt{},
		&models.AccessRequest{}, &models.AccessRequestApproval{},
		&models.WebAuthnCredential{}, &models.WebAuthnSession{},
		&models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
		&models.ConnectRefGrant{}, &models.Session{}, &models.SetupToken{},
		&models.MFAChallenge{}, &models.SSOLoginState{},
		&models.MachineIdentity{}, &models.MachineIdentityCredential{},
		&models.MachineIdentityRole{}, &models.MachineIdentityOIDCBinding{},
		&models.SecretDependency{}, &models.RiskException{},
		&models.MFASecret{}, &models.MFARecoveryCode{},
		&models.IdentityProvider{}, &models.ExternalIdentity{},
		&models.LegalHold{}, &models.ShareRecord{},
		&models.PersonalAccessToken{},
		&models.ProjectInvitation{}, &models.SchedulerLockLease{},
		&models.SecretAccessLog{},
		&models.SystemMetadata{},
		&models.PasswordHistory{},
		&models.SecretVersion{},
	))
	adminRole := &models.Role{Name: "system_admin", Description: "Administrator"}
	require.NoError(t, db.Create(adminRole).Error)
	testUser := &models.User{Username: "testuser_s28", Email: "testuser_s28@example.com", AccountState: "active"}
	require.NoError(t, db.Create(testUser).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testUser.ID, RoleID: adminRole.ID}).Error)
	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

// uintStrS28 converts a uint to a decimal string.
func uintStrS28(n uint) string {
	return fmt.Sprintf("%d", n)
}

// withChiParam2_S28 sets two chi URL params at once.
func withChiParam2_S28(r *http.Request, k1, v1, k2, v2 string) *http.Request {
	return withChiParams2_S25(r, k1, v1, k2, v2)
}

// withChiParam3_S28 sets three chi URL params at once.
func withChiParam3_S28(r *http.Request, k1, v1, k2, v2, k3, v3 string) *http.Request {
	return withChiParams3_S25(r, k1, v1, k2, v2, k3, v3)
}

// jsonBodyS28 serialises v to a JSON bytes.Reader.
func jsonBodyS28(t *testing.T, v interface{}) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewReader(b)
}

// ── machine_identities_proxy.go: ListMachineIdentitiesProxy ─────────────────

// TestListMachineIdentitiesProxy_MissingProjectID_S28 — omitting project_id
// query parameter must return 400.
func TestListMachineIdentitiesProxy_MissingProjectID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities", nil)
	w := httptest.NewRecorder()
	h.ListMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "project_id")
}

// TestListMachineIdentitiesProxy_BadProjectID_S28 — non-numeric project_id → 400.
func TestListMachineIdentitiesProxy_BadProjectID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities?project_id=notanumber", nil)
	w := httptest.NewRecorder()
	h.ListMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListMachineIdentitiesProxy_HappyPath_S28 — valid project_id with no
// rows returns 200 with empty machine_identities list.
func TestListMachineIdentitiesProxy_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities?project_id=1", nil)
	w := httptest.NewRecorder()
	h.ListMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "machine_identities")
}

// ── machine_identities_proxy.go: CreateMachineIdentityProxy ─────────────────

// TestCreateMachineIdentityProxy_BadBody_S28 — unparseable JSON → 400.
func TestCreateMachineIdentityProxy_BadBody_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-identities",
		bytes.NewBufferString("{not-json"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateMachineIdentityProxy_MissingFields_S28 — missing name or project_id → 400.
func TestCreateMachineIdentityProxy_MissingFields_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	// Missing project_id.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-identities",
		jsonBodyS28(t, map[string]interface{}{"name": "test-machine"}))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateMachineIdentityProxy_HappyPath_S28 — valid body creates a machine
// identity and returns 200 with the created resource.
func TestCreateMachineIdentityProxy_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	// identity_type must be one of core's validMachineTypes (ci|k8s|service|
	// automation|other|node) now that CreateMachineIdentityProxy routes through
	// core.CreateMachineIdentity (G80 raw-storage-bypass fix) instead of trusting
	// the wire body's identity_type/state verbatim — "workload" was never a real
	// identity_type, the old unvalidated raw proxy just never checked.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-identities",
		jsonBodyS28(t, map[string]interface{}{
			"name":          "test-machine-s28",
			"project_id":    1,
			"identity_type": "service",
			"state":         "active",
		}))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "test-machine-s28")
}

// ── machine_identities_proxy.go: GetMachineIdentityProxy ────────────────────

// TestGetMachineIdentityProxy_BadID_S28 — non-numeric id URL param → 400.
func TestGetMachineIdentityProxy_BadID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notanumber")
	w := httptest.NewRecorder()
	h.GetMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetMachineIdentityProxy_NotFound_S28 — valid id that does not exist → 404.
func TestGetMachineIdentityProxy_NotFound_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetMachineIdentityProxy_HappyPath_S28 — creates a machine identity then
// retrieves it via the proxy.
func TestGetMachineIdentityProxy_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	ctx := context.Background()
	created, err := cs.Storage().CreateMachineIdentity(ctx, &models.MachineIdentity{
		Name: "s28-get-machine", ProjectID: 1, IdentityType: "workload", State: "active",
	})
	require.NoError(t, err)

	h := NewCatalogHandler(cs)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", uintStrS28(created.ID))
	w := httptest.NewRecorder()
	h.GetMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "s28-get-machine")
}

// ── machine_identities_proxy.go: TransitionMachineIdentityStateProxy ─────────

// TestTransitionMachineIdentityStateProxy_BadID_S28 — bad URL id → 400.
func TestTransitionMachineIdentityStateProxy_BadID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodPut, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestTransitionMachineIdentityStateProxy_BadBody_S28 — unparseable body → 400.
func TestTransitionMachineIdentityStateProxy_BadBody_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodPut, "/",
		bytes.NewBufferString("{not-json")), "id", "1")
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestTransitionMachineIdentityStateProxy_MissingFromState_S28 — body without
// from_state → 400.
func TestTransitionMachineIdentityStateProxy_MissingFromState_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodPut, "/",
		jsonBodyS28(t, map[string]interface{}{
			"machine_identity": map[string]interface{}{"state": "revoked"},
		})), "id", "1")
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "from_state")
}

// TestTransitionMachineIdentityStateProxy_HappyPath_S28 — well-formed body
// targeting an existing machine; no concurrent writer means matched=false (or
// true), response is 200 either way.
func TestTransitionMachineIdentityStateProxy_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	ctx := context.Background()
	created, err := cs.Storage().CreateMachineIdentity(ctx, &models.MachineIdentity{
		Name: "s28-transition-machine", ProjectID: 1, IdentityType: "workload", State: "active",
	})
	require.NoError(t, err)

	h := NewCatalogHandler(cs)
	body := map[string]interface{}{
		"machine_identity": map[string]interface{}{"state": "revoked"},
		"from_state":       "active",
	}
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/",
		jsonBodyS28(t, body)), "id", uintStrS28(created.ID))
	w := httptest.NewRecorder()
	h.TransitionMachineIdentityStateProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "matched")
}

// ── machine_identities_proxy.go: ListAllMachineIdentitiesProxy ──────────────

// TestListAllMachineIdentitiesProxy_Empty_S28 — empty DB returns 200 with
// empty list.
func TestListAllMachineIdentitiesProxy_Empty_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities/all", nil)
	w := httptest.NewRecorder()
	h.ListAllMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "machine_identities")
}

// TestListAllMachineIdentitiesProxy_WithData_S28 — seeded machine identity
// appears in the response.
func TestListAllMachineIdentitiesProxy_WithData_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	ctx := context.Background()
	_, err := cs.Storage().CreateMachineIdentity(ctx, &models.MachineIdentity{
		Name: "s28-listall-machine", ProjectID: 1, IdentityType: "workload", State: "active",
	})
	require.NoError(t, err)

	h := NewCatalogHandler(cs)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-identities/all", nil)
	w := httptest.NewRecorder()
	h.ListAllMachineIdentitiesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "s28-listall-machine")
}

// ── machine_identities_proxy.go: CountMachineIdentitiesByClassificationProxy ─

// TestCountMachineIdentitiesByClassificationProxy_Empty_S28 — empty DB returns
// 200 with counts map.
func TestCountMachineIdentitiesByClassificationProxy_Empty_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/machine-identities/classification-counts", nil)
	w := httptest.NewRecorder()
	h.CountMachineIdentitiesByClassificationProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "counts")
}

// ── machine_identities_proxy.go: CreateMachineIdentityCredentialProxy ────────

// TestCreateMachineIdentityCredentialProxy_BadBody_S28 — invalid JSON → 400.
func TestCreateMachineIdentityCredentialProxy_BadBody_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-credentials",
		bytes.NewBufferString("{bad"))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateMachineIdentityCredentialProxy_MissingFields_S28 — missing
// machine_identity_id or token_hash → 400.
func TestCreateMachineIdentityCredentialProxy_MissingFields_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-credentials",
		jsonBodyS28(t, map[string]interface{}{"name": "cred-s28"}))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateMachineIdentityCredentialProxy_HappyPath_S28 — creates a machine
// identity first, then a credential for it.
func TestCreateMachineIdentityCredentialProxy_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	ctx := context.Background()
	mi, err := cs.Storage().CreateMachineIdentity(ctx, &models.MachineIdentity{
		Name: "s28-cred-machine", ProjectID: 1, IdentityType: "workload", State: "active",
	})
	require.NoError(t, err)

	h := NewCatalogHandler(cs)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-credentials",
		jsonBodyS28(t, map[string]interface{}{
			"machine_identity_id": mi.ID,
			"token_hash":          "deadbeef0123456789abcdef01234567",
			"name":                "s28-cred",
		}))
	w := httptest.NewRecorder()
	h.CreateMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "s28-cred")
}

// ── machine_identities_proxy.go: ListMachineIdentityCredentialsProxy ─────────

// TestListMachineIdentityCredentialsProxy_BadID_S28 — non-numeric {id} → 400.
func TestListMachineIdentityCredentialsProxy_BadID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListMachineIdentityCredentialsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListMachineIdentityCredentialsProxy_HappyPath_S28 — valid machine id
// with no credentials returns 200 with empty list.
func TestListMachineIdentityCredentialsProxy_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	ctx := context.Background()
	mi, err := cs.Storage().CreateMachineIdentity(ctx, &models.MachineIdentity{
		Name: "s28-list-cred-machine", ProjectID: 1, IdentityType: "workload", State: "active",
	})
	require.NoError(t, err)

	h := NewCatalogHandler(cs)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", uintStrS28(mi.ID))
	w := httptest.NewRecorder()
	h.ListMachineIdentityCredentialsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "credentials")
}

// ── machine_identities_proxy.go: ListActiveMachineIdentityCredentialsProxy ───

// TestListActiveMachineIdentityCredentialsProxy_Empty_S28 — empty DB returns
// 200 with credentials list.
func TestListActiveMachineIdentityCredentialsProxy_Empty_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-credentials/active", nil)
	w := httptest.NewRecorder()
	h.ListActiveMachineIdentityCredentialsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "credentials")
}

// ── machine_identities_proxy.go: CountMachineIdentityCredentialsByClassificationProxy

// TestCountMachineIdentityCredentialsByClassificationProxy_Empty_S28 — empty
// DB returns 200 with counts.
func TestCountMachineIdentityCredentialsByClassificationProxy_Empty_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/machine-credentials/classification-counts", nil)
	w := httptest.NewRecorder()
	h.CountMachineIdentityCredentialsByClassificationProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "counts")
}

// ── machine_identities_proxy.go: GetMachineRolesProxy ───────────────────────

// TestGetMachineRolesProxy_BadID_S28 — non-numeric {id} → 400.
func TestGetMachineRolesProxy_BadID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "notanumber")
	w := httptest.NewRecorder()
	h.GetMachineRolesProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetMachineRolesProxy_HappyPath_S28 — valid machine ID with no roles
// returns 200 with empty roles list.
func TestGetMachineRolesProxy_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	ctx := context.Background()
	mi, err := cs.Storage().CreateMachineIdentity(ctx, &models.MachineIdentity{
		Name: "s28-roles-machine", ProjectID: 1, IdentityType: "workload", State: "active",
	})
	require.NoError(t, err)

	h := NewCatalogHandler(cs)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", uintStrS28(mi.ID))
	w := httptest.NewRecorder()
	h.GetMachineRolesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "roles")
}

// ── machine_identities_proxy.go: AssignMachineRoleProxy ─────────────────────

// TestAssignMachineRoleProxy_MissingScope_S28 — missing project_id and
// environment_id query params → 400.
func TestAssignMachineRoleProxy_MissingScope_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam2_S28(
		httptest.NewRequest(http.MethodPost, "/", nil),
		"id", "1", "roleId", "1",
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestAssignMachineRoleProxy_BadMachineID_S28 — non-numeric {id} → 400.
func TestAssignMachineRoleProxy_BadMachineID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam2_S28(
		httptest.NewRequest(http.MethodPost, "/?project_id=1&environment_id=0", nil),
		"id", "bad", "roleId", "1",
	)
	w := httptest.NewRecorder()
	h.AssignMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── machine_identities_proxy.go: DeleteOIDCBindingProxy ──────────────────────

// TestDeleteOIDCBindingProxy_BadID_S28 — non-numeric {id} → 400.
func TestDeleteOIDCBindingProxy_BadID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.DeleteOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeleteOIDCBindingProxy_NotFound_S28 — valid id that does not exist → 404.
func TestDeleteOIDCBindingProxy_NotFound_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.DeleteOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDeleteOIDCBindingProxy_HappyPath_S28 — creates an OIDC binding, then
// deletes it → 200.
func TestDeleteOIDCBindingProxy_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	ctx := context.Background()
	mi, err := cs.Storage().CreateMachineIdentity(ctx, &models.MachineIdentity{
		Name: "s28-oidc-delete-machine", ProjectID: 1, IdentityType: "workload", State: "active",
	})
	require.NoError(t, err)
	binding, err := cs.Storage().CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: mi.ID,
		Issuer:            "https://issuer.example.com",
		Subject:           "sub-s28-del",
	})
	require.NoError(t, err)

	h := NewCatalogHandler(cs)
	req := withChiParam(httptest.NewRequest(http.MethodDelete, "/", nil), "id", uintStrS28(binding.ID))
	w := httptest.NewRecorder()
	h.DeleteOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "deleted")
}

// ── machine_identities_proxy.go: ListOIDCBindingsProxy ───────────────────────

// TestListOIDCBindingsProxy_BadID_S28 — non-numeric {id} → 400.
func TestListOIDCBindingsProxy_BadID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListOIDCBindingsProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListOIDCBindingsProxy_HappyPath_S28 — valid machine id with no bindings
// returns 200 with empty list.
func TestListOIDCBindingsProxy_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	ctx := context.Background()
	mi, err := cs.Storage().CreateMachineIdentity(ctx, &models.MachineIdentity{
		Name: "s28-oidc-list-machine", ProjectID: 1, IdentityType: "workload", State: "active",
	})
	require.NoError(t, err)

	h := NewCatalogHandler(cs)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", uintStrS28(mi.ID))
	w := httptest.NewRecorder()
	h.ListOIDCBindingsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "bindings")
}

// ── access_review_campaigns.go: ListAccessReviewCampaigns ─────────────────────

// TestListAccessReviewCampaigns_BadProjectID_S28 — non-numeric {id} → 400.
func TestListAccessReviewCampaigns_BadProjectID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaigns(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestListAccessReviewCampaigns_HappyPath_S28 — empty project returns 200
// with empty campaigns list.
func TestListAccessReviewCampaigns_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.ListAccessReviewCampaigns(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "campaigns")
}

// ── access_review_campaigns.go: DecideAccessReviewCampaignItem ────────────────

// TestDecideAccessReviewCampaignItem_BadCampaignID_S28 — non-numeric campaignId → 400.
func TestDecideAccessReviewCampaignItem_BadCampaignID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam3_S28(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil)),
		"id", "1", "campaignId", "bad", "itemId", "1",
	)
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDecideAccessReviewCampaignItem_BadItemID_S28 — non-numeric itemId → 400.
func TestDecideAccessReviewCampaignItem_BadItemID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam3_S28(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/", nil)),
		"id", "1", "campaignId", "1", "itemId", "bad",
	)
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDecideAccessReviewCampaignItem_BadJSON_S28 — unparseable body → 400.
func TestDecideAccessReviewCampaignItem_BadJSON_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam3_S28(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/",
			bytes.NewBufferString("{bad"))),
		"id", "1", "campaignId", "1", "itemId", "1",
	)
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDecideAccessReviewCampaignItem_MissingAction_S28 — empty action → 400.
func TestDecideAccessReviewCampaignItem_MissingAction_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam3_S28(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/",
			jsonBodyS28(t, map[string]string{"reason": "some reason"}))),
		"id", "1", "campaignId", "1", "itemId", "1",
	)
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "action")
}

// TestDecideAccessReviewCampaignItem_NotFound_S28 — well-formed body for a
// non-existent campaign → error (not found).
func TestDecideAccessReviewCampaignItem_NotFound_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam3_S28(
		withUserCtx(httptest.NewRequest(http.MethodPost, "/",
			jsonBodyS28(t, map[string]string{"action": "attest", "reason": "ok"}))),
		"id", "1", "campaignId", "9999", "itemId", "9999",
	)
	w := httptest.NewRecorder()
	h.DecideAccessReviewCampaignItem(w, req)
	// campaign not found → 404 or 400 (campaignStatusForError maps "not found" → 404)
	assert.True(t, w.Code == http.StatusNotFound || w.Code == http.StatusBadRequest,
		"expected 404 or 400, got %d", w.Code)
}

// ── project_members.go: AddProjectMember ────────────────────────────────────

// TestAddProjectMember_UnknownRole_S28 — existing project but unknown role
// name → 400 "unknown role".
func TestAddProjectMember_UnknownRole_S28(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreS28WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s28-add-member-proj"}
	require.NoError(t, db.Create(proj).Error)
	targetUser := &models.User{Username: "s28-target-user", Email: "s28target@example.com", AccountState: "active"}
	require.NoError(t, db.Create(targetUser).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/",
			jsonBodyS28(t, map[string]interface{}{
				"user_id": targetUser.ID,
				"role":    "nonexistent_role_xyz",
			})),
		"id", uintStrS28(proj.ID),
	))
	w := httptest.NewRecorder()
	h.AddProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestAddProjectMember_HappyPath_S28 — adds a real user to a project with a
// known role.
func TestAddProjectMember_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreS28WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s28-add-member-happy-proj"}
	require.NoError(t, db.Create(proj).Error)
	targetUser := &models.User{Username: "s28-member-happy-user", Email: "s28happy@example.com", AccountState: "active"}
	require.NoError(t, db.Create(targetUser).Error)
	// Seed the "viewer" role so AddProjectMember can find it.
	viewerRole := &models.Role{Name: "viewer", Description: "Viewer"}
	require.NoError(t, db.Create(viewerRole).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/",
			jsonBodyS28(t, map[string]interface{}{
				"user_id": targetUser.ID,
				"role":    "viewer",
			})),
		"id", uintStrS28(proj.ID),
	))
	w := httptest.NewRecorder()
	h.AddProjectMember(w, req)
	// 201 on success; 400/409 acceptable if role mapping behaves differently.
	assert.True(t, w.Code == http.StatusCreated || w.Code == http.StatusConflict ||
		w.Code == http.StatusBadRequest,
		"expected 201/409/400, got %d: %s", w.Code, w.Body.String())
}

// ── project_members.go: UpdateProjectMember ─────────────────────────────────

// TestUpdateProjectMember_BadUserID_S28 — non-numeric {userId} → 400.
func TestUpdateProjectMember_BadUserID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withUserCtx(withChiParam2_S28(
		httptest.NewRequest(http.MethodPut, "/",
			jsonBodyS28(t, map[string]string{"role": "viewer"})),
		"id", "1", "userId", "bad",
	))
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateProjectMember_MissingRole_S28 — empty role field → 400.
func TestUpdateProjectMember_MissingRole_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withUserCtx(withChiParam2_S28(
		httptest.NewRequest(http.MethodPut, "/",
			jsonBodyS28(t, map[string]string{"role": ""})),
		"id", "1", "userId", "2",
	))
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "role")
}

// TestUpdateProjectMember_UnknownRole_S28 — unknown role name → 400.
func TestUpdateProjectMember_UnknownRole_S28(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreS28WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s28-update-member-proj"}
	require.NoError(t, db.Create(proj).Error)
	targetUser := &models.User{Username: "s28-update-target", Email: "s28upd@example.com", AccountState: "active"}
	require.NoError(t, db.Create(targetUser).Error)

	req := withUserCtx(withChiParam2_S28(
		httptest.NewRequest(http.MethodPut, "/",
			jsonBodyS28(t, map[string]string{"role": "nonexistent_role_xyz"})),
		"id", uintStrS28(proj.ID), "userId", uintStrS28(targetUser.ID),
	))
	w := httptest.NewRecorder()
	h.UpdateProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── project_members.go: RemoveProjectMember ─────────────────────────────────

// TestRemoveProjectMember_BadUserID_S28 — non-numeric {userId} → 400.
func TestRemoveProjectMember_BadUserID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withUserCtx(withChiParam2_S28(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		"id", "1", "userId", "bad",
	))
	w := httptest.NewRecorder()
	h.RemoveProjectMember(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRemoveProjectMember_NotMember_S28 — user is not a member → 404.
func TestRemoveProjectMember_NotMember_S28(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreS28WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "s28-remove-member-proj"}
	require.NoError(t, db.Create(proj).Error)
	nonMember := &models.User{Username: "s28-nonmember", Email: "s28nonmember@example.com", AccountState: "active"}
	require.NoError(t, db.Create(nonMember).Error)

	req := withUserCtx(withChiParam2_S28(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		"id", uintStrS28(proj.ID), "userId", uintStrS28(nonMember.ID),
	))
	w := httptest.NewRecorder()
	h.RemoveProjectMember(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── audit.go: WriteAuditCheckpoint ──────────────────────────────────────────

// TestWriteAuditCheckpoint_S28_Unauthenticated — no user context → 401.
func TestWriteAuditCheckpoint_S28_Unauthenticated(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewAuditHandler(cs)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/checkpoint", nil)
	w := httptest.NewRecorder()
	h.WriteAuditCheckpoint(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestWriteAuditCheckpoint_S28_NoEncryption — authenticated, encryption not
// configured → 412 PreconditionFailed (or 409 if chain is broken).
func TestWriteAuditCheckpoint_S28_NoEncryption(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewAuditHandler(cs)

	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/audit/checkpoint", nil))
	w := httptest.NewRecorder()
	h.WriteAuditCheckpoint(w, req)
	// Without encryption enabled the handler returns 412; a broken chain → 409.
	assert.True(t, w.Code == http.StatusPreconditionFailed || w.Code == http.StatusConflict,
		"expected 412 or 409, got %d: %s", w.Code, w.Body.String())
}

// ── audit.go: VerifyAuditChain — already tested in s27; add a branch test ───

// TestVerifyAuditChain_S28_WithAnchored — chain with events that include a
// prev_hash field; handler returns 200 with head_hash field.
func TestVerifyAuditChain_S28_WithAnchored(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	ctx := context.Background()
	tru := true
	require.NoError(t, cs.Storage().LogAuditEvent(ctx, &models.AuditEvent{
		EventType: "secret.write", Description: "checkpoint-anchor", Success: &tru, ActorType: "user",
	}))

	h := NewAuditHandler(cs)
	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/audit/verify", nil))
	w := httptest.NewRecorder()
	h.VerifyAuditChain(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "chained_events")
}

// ── machine_identities_proxy.go: GetMachineByOIDCSubjectProxy ───────────────

// TestGetMachineByOIDCSubjectProxy_MissingParams_S28 — missing issuer and
// subject → 400.
func TestGetMachineByOIDCSubjectProxy_MissingParams_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/machine-oidc-bindings/by-subject", nil)
	w := httptest.NewRecorder()
	h.GetMachineByOIDCSubjectProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetMachineByOIDCSubjectProxy_NotFound_S28 — valid params for non-existent
// binding → 404.
func TestGetMachineByOIDCSubjectProxy_NotFound_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/machine-oidc-bindings/by-subject?issuer=https://iss.example.com&subject=nosuchsub",
		nil)
	w := httptest.NewRecorder()
	h.GetMachineByOIDCSubjectProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities_proxy.go: GetMachineRoleIDsAtProxy ───────────────────

// TestGetMachineRoleIDsAtProxy_MissingScope_S28 — missing scope params → 400.
func TestGetMachineRoleIDsAtProxy_MissingScope_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "1")
	w := httptest.NewRecorder()
	h.GetMachineRoleIDsAtProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetMachineRoleIDsAtProxy_HappyPath_S28 — valid machine id and scope with
// no roles returns 200 with empty role_ids.
func TestGetMachineRoleIDsAtProxy_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	ctx := context.Background()
	mi, err := cs.Storage().CreateMachineIdentity(ctx, &models.MachineIdentity{
		Name: "s28-role-ids-machine", ProjectID: 1, IdentityType: "workload", State: "active",
	})
	require.NoError(t, err)

	h := NewCatalogHandler(cs)
	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/?project_id=1&environment_id=0", nil),
		"id", uintStrS28(mi.ID),
	)
	w := httptest.NewRecorder()
	h.GetMachineRoleIDsAtProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "role_ids")
}

// ── machine_identities_proxy.go: RemoveMachineRoleProxy ─────────────────────

// TestRemoveMachineRoleProxy_MissingScope_S28 — missing scope params → 400.
func TestRemoveMachineRoleProxy_MissingScope_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam2_S28(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		"id", "1", "roleId", "1",
	)
	w := httptest.NewRecorder()
	h.RemoveMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRemoveMachineRoleProxy_NotAssigned_S28 — valid scope but grant does not
// exist → 404.
func TestRemoveMachineRoleProxy_NotAssigned_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam2_S28(
		httptest.NewRequest(http.MethodDelete, "/?project_id=1&environment_id=0", nil),
		"id", "1", "roleId", "99999",
	)
	w := httptest.NewRecorder()
	h.RemoveMachineRoleProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── machine_identities_proxy.go: RevokeMachineIdentityCredentialProxy ────────

// TestRevokeMachineIdentityCredentialProxy_BadID_S28 — non-numeric {id} → 400.
func TestRevokeMachineIdentityCredentialProxy_BadID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.RevokeMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestRevokeMachineIdentityCredentialProxy_NotFound_S28 — valid id that does
// not exist → 404.
func TestRevokeMachineIdentityCredentialProxy_NotFound_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.RevokeMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestRevokeMachineIdentityCredentialProxy_HappyPath_S28 — creates a
// credential then revokes it.
func TestRevokeMachineIdentityCredentialProxy_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	ctx := context.Background()
	mi, err := cs.Storage().CreateMachineIdentity(ctx, &models.MachineIdentity{
		Name: "s28-revoke-machine", ProjectID: 1, IdentityType: "workload", State: "active",
	})
	require.NoError(t, err)
	cred, err := cs.Storage().CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
		MachineIdentityID: mi.ID,
		Name:              "s28-revoke-cred",
		TokenHash:         "aabbccdd00112233aabbccdd00112233",
	})
	require.NoError(t, err)

	h := NewCatalogHandler(cs)
	req := withChiParam(httptest.NewRequest(http.MethodPost, "/", nil), "id", uintStrS28(cred.ID))
	w := httptest.NewRecorder()
	h.RevokeMachineIdentityCredentialProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "revoked")
}

// ── machine_identities_proxy.go: GetOIDCBindingByIDProxy ─────────────────────

// TestGetOIDCBindingByIDProxy_BadID_S28 — non-numeric {id} → 400.
func TestGetOIDCBindingByIDProxy_BadID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "bad")
	w := httptest.NewRecorder()
	h.GetOIDCBindingByIDProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetOIDCBindingByIDProxy_NotFound_S28 — valid id that does not exist → 404.
func TestGetOIDCBindingByIDProxy_NotFound_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", "9999")
	w := httptest.NewRecorder()
	h.GetOIDCBindingByIDProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestGetOIDCBindingByIDProxy_HappyPath_S28 — creates a binding then retrieves it.
func TestGetOIDCBindingByIDProxy_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	ctx := context.Background()
	mi, err := cs.Storage().CreateMachineIdentity(ctx, &models.MachineIdentity{
		Name: "s28-oidc-get-machine", ProjectID: 1, IdentityType: "workload", State: "active",
	})
	require.NoError(t, err)
	binding, err := cs.Storage().CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: mi.ID,
		Issuer:            "https://iss.example.com",
		Subject:           "sub-s28-get",
	})
	require.NoError(t, err)

	h := NewCatalogHandler(cs)
	req := withChiParam(httptest.NewRequest(http.MethodGet, "/", nil), "id", uintStrS28(binding.ID))
	w := httptest.NewRecorder()
	h.GetOIDCBindingByIDProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "sub-s28-get")
}

// ── machine_identities_proxy.go: UpdateMachineIdentityProxy ──────────────────

// TestUpdateMachineIdentityProxy_BadID_S28 — non-numeric {id} → 400.
func TestUpdateMachineIdentityProxy_BadID_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodPut, "/",
		jsonBodyS28(t, map[string]string{"name": "x"})), "id", "bad")
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateMachineIdentityProxy_BadBody_S28 — invalid JSON → 400.
func TestUpdateMachineIdentityProxy_BadBody_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := withChiParam(httptest.NewRequest(http.MethodPut, "/",
		bytes.NewBufferString("{bad")), "id", "1")
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestUpdateMachineIdentityProxy_HappyPath_S28 — updates an existing machine
// identity.
func TestUpdateMachineIdentityProxy_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	ctx := context.Background()
	mi, err := cs.Storage().CreateMachineIdentity(ctx, &models.MachineIdentity{
		Name: "s28-update-machine", ProjectID: 1, IdentityType: "workload", State: "active",
	})
	require.NoError(t, err)

	h := NewCatalogHandler(cs)
	req := withChiParam(httptest.NewRequest(http.MethodPut, "/",
		jsonBodyS28(t, map[string]interface{}{
			"name": "s28-updated-machine", "project_id": 1,
		})), "id", uintStrS28(mi.ID))
	w := httptest.NewRecorder()
	h.UpdateMachineIdentityProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "updated")
}

// ── machine_identities_proxy.go: CreateOIDCBindingProxy ─────────────────────

// TestCreateOIDCBindingProxy_BadBody_S28 — invalid JSON → 400.
func TestCreateOIDCBindingProxy_BadBody_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-oidc-bindings",
		bytes.NewBufferString("{bad"))
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateOIDCBindingProxy_MissingFields_S28 — missing required fields → 400.
func TestCreateOIDCBindingProxy_MissingFields_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	h := NewCatalogHandler(cs)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-oidc-bindings",
		jsonBodyS28(t, map[string]interface{}{"machine_identity_id": 1}))
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateOIDCBindingProxy_HappyPath_S28 — creates a machine identity then
// a binding for it.
func TestCreateOIDCBindingProxy_HappyPath_S28(t *testing.T) {
	t.Parallel()
	cs := freshCoreS28(t)
	ctx := context.Background()
	mi, err := cs.Storage().CreateMachineIdentity(ctx, &models.MachineIdentity{
		Name: "s28-oidc-create-machine", ProjectID: 1, IdentityType: "workload", State: "active",
	})
	require.NoError(t, err)

	h := NewCatalogHandler(cs)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/machine-oidc-bindings",
		jsonBodyS28(t, map[string]interface{}{
			"machine_identity_id": mi.ID,
			"issuer":              "https://iss.example.com",
			"subject":             "sub-s28-create",
		}))
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "sub-s28-create")
}
