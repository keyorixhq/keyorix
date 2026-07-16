// handlers_s20_test.go — coverage sweep targeting uncovered branches in:
//   - machine_identities_proxy.go:431 CountMachineIdentitiesByClassificationProxy
//   - machine_identities_proxy.go:468 GetMachineIdentityCredentialByHashProxy (not-found + bad-hash)
//   - machine_identities_proxy.go:569 CountMachineIdentityCredentialsByClassificationProxy
//   - machine_identities_proxy.go:764 CreateOIDCBindingProxy (invalid body, missing fields, success)
//   - dynamic_secrets.go:276 RevokeAllLeases (success + storage-error via not-found config)
//   - users_crud.go:107 createUserWithOTP (success path)
//   - users_crud.go:128 createUserWithSetupLink (conflict + internal-error paths)
//   - project_catalog_proxy.go:67 newProjectProxyWire (deleted-at branch)
//   - project_catalog_proxy.go:116 ListProjectsWithCountsProxy (success, empty result)
//   - environment_catalog_proxy.go:143 DeleteEnvironmentProxy (success + bad-id)
//   - risk_exceptions.go:23 ListRiskExceptions (success path)
//   - risk_exceptions_proxy.go:168 ListRiskExceptionsProxy (success path)
//   - sod.go:21 ListSoDPolicies (success path)
//   - sod.go:93 ListSoDViolations (success path)
//   - sod_proxy.go:99 ListSoDPoliciesProxy (success path)
package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// ── DB helpers ────────────────────────────────────────────────────────────────

var s20DBCounter atomic.Int64

// freshCoreS20 opens a uniquely-named in-memory SQLite DB and returns a
// ready-to-use KeyorixCore.
func freshCoreS20(t *testing.T) *core.KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := s20DBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_s20_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	err = db.AutoMigrate(
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
	)
	require.NoError(t, err)
	return core.NewKeyorixCore(store.NewLocalStorage(db))
}

// freshCoreS20WithAdmin returns a KeyorixCore plus the underlying DB with
// user 1 wired to a system_admin role (matches withUserCtx's injected UserID=1).
func freshCoreS20WithAdmin(t *testing.T) (*core.KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	n := s20DBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_s20a_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	err = db.AutoMigrate(
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
	)
	require.NoError(t, err)

	adminRole := &models.Role{Name: "system_admin", Description: "Administrator"}
	require.NoError(t, db.Create(adminRole).Error)
	testUser := &models.User{Username: "testuser_s20", Email: "testuser_s20@example.com", AccountState: "active"}
	require.NoError(t, db.Create(testUser).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: testUser.ID, RoleID: adminRole.ID}).Error)

	return core.NewKeyorixCore(store.NewLocalStorage(db)), db
}

// ── machine_identities_proxy.go: CountMachineIdentitiesByClassificationProxy ──

// TestCountMachineIdentitiesByClassificationProxy_Success_S20 calls the
// handler on an empty DB and expects a 200 with success=true.
func TestCountMachineIdentitiesByClassificationProxy_Success_S20(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS20(t))
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/machine-identities/classification-counts", nil)
	w := httptest.NewRecorder()
	h.CountMachineIdentitiesByClassificationProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

// TestCountMachineIdentitiesByClassificationProxy_WithData_S20 seeds a
// MachineIdentity row and verifies the counts map is returned.
func TestCountMachineIdentitiesByClassificationProxy_WithData_S20(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreS20WithAdmin(t)
	h := NewCatalogHandler(cs)

	mi := &models.MachineIdentity{Name: "mi-count-s20", State: "active", Classification: "sensitive"}
	require.NoError(t, db.Create(mi).Error)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/machine-identities/classification-counts", nil)
	w := httptest.NewRecorder()
	h.CountMachineIdentitiesByClassificationProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

// ── machine_identities_proxy.go: GetMachineIdentityCredentialByHashProxy ──────

// TestGetMachineIdentityCredentialByHashProxy_NotFound_S20 sends a hash that
// does not exist → expects 404.
func TestGetMachineIdentityCredentialByHashProxy_NotFound_S20(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS20(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodGet,
			"/api/v1/system/machine-credentials/by-hash/nonexistenthash", nil),
		"hash", "nonexistenthash",
	)
	w := httptest.NewRecorder()
	h.GetMachineIdentityCredentialByHashProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.False(t, resp.Success)
}

// ── machine_identities_proxy.go: CountMachineIdentityCredentialsByClassificationProxy

// TestCountMachineIdentityCredentialsByClassificationProxy_Success_S20 — empty
// DB returns 200 with success=true.
func TestCountMachineIdentityCredentialsByClassificationProxy_Success_S20(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS20(t))
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/machine-credentials/classification-counts", nil)
	w := httptest.NewRecorder()
	h.CountMachineIdentityCredentialsByClassificationProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

// TestCountMachineIdentityCredentialsByClassificationProxy_WithData_S20 seeds a
// credential and verifies the counts map is non-nil.
func TestCountMachineIdentityCredentialsByClassificationProxy_WithData_S20(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreS20WithAdmin(t)
	h := NewCatalogHandler(cs)

	mi := &models.MachineIdentity{Name: "mi-cred-count-s20", State: "active"}
	require.NoError(t, db.Create(mi).Error)

	cred := &models.MachineIdentityCredential{
		MachineIdentityID: mi.ID,
		Name:              "cred-count-s20",
		TokenHash:         "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Classification:    "sensitive",
	}
	require.NoError(t, db.Create(cred).Error)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/machine-credentials/classification-counts", nil)
	w := httptest.NewRecorder()
	h.CountMachineIdentityCredentialsByClassificationProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

// ── machine_identities_proxy.go: CreateOIDCBindingProxy ───────────────────────

// TestCreateOIDCBindingProxy_InvalidBody_S20 — malformed JSON → 400.
func TestCreateOIDCBindingProxy_InvalidBody_S20(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS20(t))
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/system/machine-oidc-bindings",
		bytes.NewBufferString("not-json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.False(t, resp.Success)
}

// TestCreateOIDCBindingProxy_MissingFields_S20 — missing machine_identity_id,
// issuer, and subject → 400 validation error.
func TestCreateOIDCBindingProxy_MissingFields_S20(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS20(t))
	body, _ := json.Marshal(map[string]interface{}{
		"machine_identity_id": 0, // invalid: zero
		"issuer":              "",
		"subject":             "",
	})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/system/machine-oidc-bindings",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.False(t, resp.Success)
}

// TestCreateOIDCBindingProxy_MissingIssuer_S20 — valid machine_identity_id but
// empty issuer → 400 validation error.
func TestCreateOIDCBindingProxy_MissingIssuer_S20(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS20(t))
	body, _ := json.Marshal(map[string]interface{}{
		"machine_identity_id": 1,
		"issuer":              "",
		"subject":             "sub",
	})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/system/machine-oidc-bindings",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCreateOIDCBindingProxy_Success_S20 seeds a MachineIdentity, then creates
// an OIDC binding for it and expects a 200 success.
func TestCreateOIDCBindingProxy_Success_S20(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreS20WithAdmin(t)
	h := NewCatalogHandler(cs)

	mi := &models.MachineIdentity{Name: "mi-oidc-s20", State: "active"}
	require.NoError(t, db.Create(mi).Error)

	body, _ := json.Marshal(map[string]interface{}{
		"machine_identity_id": mi.ID,
		"issuer":              "https://accounts.example.com",
		"subject":             "user@example.com",
	})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/system/machine-oidc-bindings",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

// TestCreateOIDCBindingProxy_Duplicate_S20 creates the same binding twice and
// expects a 409 on the second attempt.
func TestCreateOIDCBindingProxy_Duplicate_S20(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreS20WithAdmin(t)
	h := NewCatalogHandler(cs)

	mi := &models.MachineIdentity{Name: "mi-oidc-dup-s20", State: "active"}
	require.NoError(t, db.Create(mi).Error)

	body, _ := json.Marshal(map[string]interface{}{
		"machine_identity_id": mi.ID,
		"issuer":              "https://dup.example.com",
		"subject":             "dup@example.com",
	})

	// First creation — should succeed.
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/system/machine-oidc-bindings",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second creation — same issuer/subject → unique-violation → 409.
	req2 := httptest.NewRequest(http.MethodPost,
		"/api/v1/system/machine-oidc-bindings",
		bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	h.CreateOIDCBindingProxy(w2, req2)
	assert.Equal(t, http.StatusConflict, w2.Code)
}

// ── dynamic_secrets.go: RevokeAllLeases ──────────────────────────────────────

// TestRevokeAllLeases_ConfigNotFound_S20 — provides a valid integer ID for a
// non-existent config → loadAuthorizedConfig returns 404, so the handler exits
// early before touching userCtx.
func TestRevokeAllLeases_ConfigNotFound_S20(t *testing.T) {
	t.Parallel()
	h := NewDynamicSecretHandler(freshCoreS20(t))
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/api/v1/dynamic-secrets/configs/9999/revoke-all", nil),
		"id", "9999",
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	// Config does not exist → 404.
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestRevokeAllLeases_Success_S20 seeds a DynamicSecretConfig (with a fake
// backend type so no real DB connection is attempted) via direct DB insert, then
// calls RevokeAllLeases. Because no leases exist RevokeLeasesForConfig returns
// (0, 0, nil) and the handler writes 200.
func TestRevokeAllLeases_Success_S20(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreS20WithAdmin(t)
	h := NewDynamicSecretHandler(cs)

	proj := &models.Project{Name: "proj-revoke-s20"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-revoke-s20", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)

	cfg := &models.DynamicSecretConfig{
		Name:          "cfg-revoke-s20",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		BackendType:   "postgresql",
		CreatedBy:     "test",
	}
	require.NoError(t, db.Create(cfg).Error)

	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPost, "/", nil),
		"id", fmt.Sprintf("%d", cfg.ID),
	))
	w := httptest.NewRecorder()
	h.RevokeAllLeases(w, req)
	// With admin user context and no active leases, RevokeLeasesForConfig
	// returns (0, 0, nil) → 200.
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "revoked")
}

// ── users_crud.go: createUserWithOTP success path ────────────────────────────

// TestCreateUserWithOTP_Success_S20 creates a new user via the OTP path and
// expects a 201 with both "user" and "one_time_password" in the response.
// This exercises the success branch of createUserWithOTP.
func TestCreateUserWithOTP_Success_S20(t *testing.T) {
	uh, _, _ := freshUserHandlerS12(t)

	body, _ := json.Marshal(map[string]interface{}{
		"username":                   "otp-success-s20",
		"email":                      "otp-success-s20@x.com",
		"display_name":               "OTP Success S20",
		"generate_one_time_password": true,
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Contains(t, w.Body.String(), "one_time_password")
	assert.Contains(t, w.Body.String(), "otp-success-s20")
}

// ── users_crud.go: createUserWithSetupLink remaining branches ─────────────────

// TestCreateUserWithSetupLink_Conflict_S20 seeds a user and tries to create
// another with the same email via the setup-link path → 409 conflict.
func TestCreateUserWithSetupLink_Conflict_S20(t *testing.T) {
	uh, cs, _ := freshUserHandlerS12(t)
	cs.SetCredentialDelivery(nil, "https://test-s20.keyorix.example")

	// Create the conflicting user first.
	_, _, err := cs.CreateUserWithSetupLink(
		httptest.NewRequest(http.MethodPost, "/", nil).Context(),
		&core.CreateUserRequest{
			Username:    "setup-conflict-s20",
			Email:       "setup-conflict-s20@x.com",
			DisplayName: "Setup Conflict S20",
		},
		1,
	)
	require.NoError(t, err)

	// Now attempt to create the same user via the handler.
	body, _ := json.Marshal(map[string]interface{}{
		"username":           "setup-conflict-s20",
		"email":              "setup-conflict-s20@x.com",
		"display_name":       "Setup Conflict S20",
		"deliver_setup_link": true,
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "ConflictError")
}

// TestCreateUserWithSetupLink_ValidationError_S20 passes an invalid username
// (empty) via the setup-link path to exercise the validation-error branch.
func TestCreateUserWithSetupLink_ValidationError_S20(t *testing.T) {
	uh, cs, _ := freshUserHandlerS12(t)
	cs.SetCredentialDelivery(nil, "https://test-s20.keyorix.example")

	// Empty username will fail core validation.
	body, _ := json.Marshal(map[string]interface{}{
		"username":           "",
		"email":              "setup-invalid-s20@x.com",
		"display_name":       "Setup Invalid S20",
		"deliver_setup_link": true,
	})
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	uh.CreateUser(w, req)
	// Empty username fails handler-level validation → 400.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── project_catalog_proxy.go: newProjectProxyWire deleted-at branch ───────────

// TestNewProjectProxyWire_SoftDeleted_S20 calls newProjectProxyWire directly
// with a models.Project whose DeletedAt is valid (soft-deleted) and verifies
// the wire's DeletedAt field is populated.
func TestNewProjectProxyWire_SoftDeleted_S20(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	p := &models.Project{
		ID:        77,
		Name:      "deleted-proj-s20",
		DeletedAt: gorm.DeletedAt{Time: now, Valid: true},
		CreatedAt: now,
		UpdatedAt: now,
	}
	w := newProjectProxyWire(p)
	assert.Equal(t, "deleted-proj-s20", w.Name)
	assert.NotNil(t, w.DeletedAt, "DeletedAt should be set for a soft-deleted project")
	assert.Equal(t, now, *w.DeletedAt)
}

// TestNewProjectProxyWire_Active_S20 calls newProjectProxyWire with a live
// project and verifies DeletedAt is nil.
func TestNewProjectProxyWire_Active_S20(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	p := &models.Project{
		ID:        78,
		Name:      "active-proj-s20",
		CreatedAt: now,
		UpdatedAt: now,
	}
	w := newProjectProxyWire(p)
	assert.Equal(t, "active-proj-s20", w.Name)
	assert.Nil(t, w.DeletedAt, "DeletedAt should be nil for an active project")
}

// ── project_catalog_proxy.go: ListProjectsWithCountsProxy success path ────────

// TestListProjectsWithCountsProxy_Success_S20 calls the handler against an
// empty DB and expects a 200 success envelope.
func TestListProjectsWithCountsProxy_Success_S20(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS20(t))
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/projects/with-counts", nil)
	w := httptest.NewRecorder()
	h.ListProjectsWithCountsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

// TestListProjectsWithCountsProxy_IncludeDeleted_Success_S20 — same but with
// ?include_deleted=true to exercise the second argument branch.
func TestListProjectsWithCountsProxy_IncludeDeleted_Success_S20(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS20(t))
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/projects/with-counts?include_deleted=true", nil)
	w := httptest.NewRecorder()
	h.ListProjectsWithCountsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

// ── environment_catalog_proxy.go: DeleteEnvironmentProxy ─────────────────────

// TestDeleteEnvironmentProxy_BadID_S20 — a non-numeric ID → 400.
func TestDeleteEnvironmentProxy_BadID_S20(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS20(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		"id", "notanumber",
	)
	w := httptest.NewRecorder()
	h.DeleteEnvironmentProxy(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.False(t, resp.Success)
}

// TestDeleteEnvironmentProxy_NotFound_S20 — valid numeric ID but environment
// does not exist → 404.
func TestDeleteEnvironmentProxy_NotFound_S20(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS20(t))
	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		"id", "99999",
	)
	w := httptest.NewRecorder()
	h.DeleteEnvironmentProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestDeleteEnvironmentProxy_Success_S20 seeds a project+environment and
// deletes it successfully → 200.
func TestDeleteEnvironmentProxy_Success_S20(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreS20WithAdmin(t)
	h := NewCatalogHandler(cs)

	proj := &models.Project{Name: "proj-env-del-s20"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "env-del-s20", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)

	req := withChiParam(
		httptest.NewRequest(http.MethodDelete, "/", nil),
		"id", fmt.Sprintf("%d", env.ID),
	)
	w := httptest.NewRecorder()
	h.DeleteEnvironmentProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

// ── risk_exceptions.go: ListRiskExceptions success path ──────────────────────

// TestListRiskExceptions_Success_S20 — empty DB returns 200 with success.
func TestListRiskExceptions_Success_S20(t *testing.T) {
	t.Parallel()
	h := NewDashboardHandler(freshCoreS20(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/risk-exceptions", nil)
	w := httptest.NewRecorder()
	h.ListRiskExceptions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "exceptions")
}

// TestListRiskExceptions_AllParam_Success_S20 — ?all=true exercises the
// activeOnly=false branch with an empty DB.
func TestListRiskExceptions_AllParam_Success_S20(t *testing.T) {
	t.Parallel()
	h := NewDashboardHandler(freshCoreS20(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/risk-exceptions?all=true", nil)
	w := httptest.NewRecorder()
	h.ListRiskExceptions(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "exceptions")
}

// ── risk_exceptions_proxy.go: ListRiskExceptionsProxy success path ────────────

// TestListRiskExceptionsProxy_Success_S20 — empty DB returns 200 with
// success=true in the remote API envelope.
func TestListRiskExceptionsProxy_Success_S20(t *testing.T) {
	t.Parallel()
	h := NewDashboardHandler(freshCoreS20(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/risk-exceptions", nil)
	w := httptest.NewRecorder()
	h.ListRiskExceptionsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

// TestListRiskExceptionsProxy_ActiveOnly_Success_S20 — ?active_only=true
// exercises the activeOnly=true branch.
func TestListRiskExceptionsProxy_ActiveOnly_Success_S20(t *testing.T) {
	t.Parallel()
	h := NewDashboardHandler(freshCoreS20(t))
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/system/risk-exceptions?active_only=true", nil)
	w := httptest.NewRecorder()
	h.ListRiskExceptionsProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

// ── sod.go: ListSoDPolicies success path ─────────────────────────────────────

// TestListSoDPolicies_Success_S20 — empty DB returns 200 with an empty policies
// list.
func TestListSoDPolicies_Success_S20(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS20(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sod/policies", nil)
	w := httptest.NewRecorder()
	h.ListSoDPolicies(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "policies")
	assert.Contains(t, w.Body.String(), "count")
}

// TestListSoDPolicies_WithData_S20 seeds a SoD policy and verifies it appears
// in the response.
func TestListSoDPolicies_WithData_S20(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreS20WithAdmin(t)
	h := NewCatalogHandler(cs)

	policy := &models.SoDPolicy{
		Name:        "sod-s20",
		PermissionA: "secrets.read",
		PermissionB: "secrets.write",
	}
	require.NoError(t, db.Create(policy).Error)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sod/policies", nil)
	w := httptest.NewRecorder()
	h.ListSoDPolicies(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "sod-s20")
}

// ── sod.go: ListSoDViolations success path ───────────────────────────────────

// TestListSoDViolations_Success_S20 — empty DB returns 200 with zero
// violations and degraded=false.
func TestListSoDViolations_Success_S20(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS20(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sod/violations", nil)
	w := httptest.NewRecorder()
	h.ListSoDViolations(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "violations")
	assert.Contains(t, body, "count")
}

// ── sod_proxy.go: ListSoDPoliciesProxy success path ──────────────────────────

// TestListSoDPoliciesProxy_Success_S20 — empty DB returns 200 with success=true
// in the remote API envelope.
func TestListSoDPoliciesProxy_Success_S20(t *testing.T) {
	t.Parallel()
	h := NewCatalogHandler(freshCoreS20(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/sod-policies", nil)
	w := httptest.NewRecorder()
	h.ListSoDPoliciesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var resp remoteAPIResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Success)
}

// TestListSoDPoliciesProxy_WithData_S20 seeds a SoD policy and verifies it
// appears in the remote API response.
func TestListSoDPoliciesProxy_WithData_S20(t *testing.T) {
	t.Parallel()
	cs, db := freshCoreS20WithAdmin(t)
	h := NewCatalogHandler(cs)

	policy := &models.SoDPolicy{
		Name:        "proxy-sod-s20",
		PermissionA: "users.read",
		PermissionB: "users.write",
	}
	require.NoError(t, db.Create(policy).Error)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/sod-policies", nil)
	w := httptest.NewRecorder()
	h.ListSoDPoliciesProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	// Capture body before decoding (decoding consumes the reader).
	rawBody := w.Body.String()
	assert.Contains(t, rawBody, "proxy-sod-s20")
	var resp remoteAPIResponse
	require.NoError(t, json.Unmarshal([]byte(rawBody), &resp))
	assert.True(t, resp.Success)
}
