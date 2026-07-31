package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newScopedTestDB creates an in-memory SQLite DB suitable for scope resolver
// and handleScopedPermissionRequest tests. It migrates only the tables needed
// for the paths under test (RBAC, environments, secrets, shares, rotation
// policies, projects).
func newScopedTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	// i18n is needed by the local storage layer for error messages.
	require.NoError(t, i18n.InitializeForTesting())
	// Use a unique per-test file URI so parallel subtests don't share state.
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Role{},
		&models.Permission{},
		&models.RolePermission{},
		&models.User{},
		&models.UserRole{},
		&models.Group{},
		&models.GroupRole{},
		&models.UserGroup{},
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.ShareRecord{},
		&models.RotationPolicy{},
		&models.AuditEvent{},
	))
	return db
}

// seedAdmin inserts a user with a global "admin" role that the RBAC admin bypass
// will recognise. Returns the user ID.
func seedAdmin(t *testing.T, db *gorm.DB, userID uint) {
	t.Helper()
	require.NoError(t, db.Create(&models.User{ID: userID, Username: "admin", AccountState: "active"}).Error)
	role := &models.Role{Name: "admin"}
	require.NoError(t, db.Create(role).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: userID, RoleID: role.ID}).Error)
}

// makeRequest builds a chi-routed request with optional URL params and places
// userCtx + coreService on its context.
func makeRequest(t *testing.T, method, path string, params map[string]string, userCtx *UserContext, cs *core.KeyorixCore) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if len(params) > 0 {
		rctx := chi.NewRouteContext()
		for k, v := range params {
			rctx.URLParams.Add(k, v)
		}
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	}
	if userCtx != nil {
		req = req.WithContext(context.WithValue(req.Context(), userContextKey, userCtx))
	}
	if cs != nil {
		req = req.WithContext(context.WithValue(req.Context(), coreServiceContextKey, cs))
	}
	return req
}

// --- handleScopedPermissionRequest coverage ---

// TestHandleScopedPermission_AllowedAdmin exercises the "allowed" path where an
// admin user has global authorization and reaches the next handler.
func TestHandleScopedPermission_AllowedAdmin(t *testing.T) {
	db := newScopedTestDB(t)
	seedAdmin(t, db, 1)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "env"}).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	userCtx := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: false, MFAEnabled: false}

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	resolver := func(_ *http.Request, _ *core.KeyorixCore) (core.Scope, error) {
		return core.Scope{ProjectID: 1, EnvironmentID: 10}, nil
	}

	req := makeRequest(t, http.MethodGet, "/test", nil, userCtx, cs)
	rec := httptest.NewRecorder()
	handleScopedPermissionRequest(next, rec, req, "secrets.read", resolver)

	assert.True(t, nextCalled, "next handler must be called for an authorized admin")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleScopedPermission_Forbidden verifies 403 when the resolver returns a
// valid scope but the user lacks the required permission.
func TestHandleScopedPermission_Forbidden(t *testing.T) {
	db := newScopedTestDB(t)
	// Non-admin user with no roles.
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "viewer", AccountState: "active"}).Error)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	userCtx := &UserContext{UserID: 2, ActorType: core.ActorTypeUser}

	resolver := func(_ *http.Request, _ *core.KeyorixCore) (core.Scope, error) {
		return core.Scope{ProjectID: 1}, nil
	}

	req := makeRequest(t, http.MethodGet, "/test", nil, userCtx, cs)
	rec := httptest.NewRecorder()
	handleScopedPermissionRequest(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), rec, req, "secrets.delete", resolver)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestHandleScopedPermission_NotFoundWithPermission verifies 404 when the
// resolver returns errTargetNotFound AND the user holds the permission globally.
func TestHandleScopedPermission_NotFoundWithPermission(t *testing.T) {
	db := newScopedTestDB(t)
	seedAdmin(t, db, 1)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	userCtx := &UserContext{UserID: 1, ActorType: core.ActorTypeUser}

	resolver := func(_ *http.Request, _ *core.KeyorixCore) (core.Scope, error) {
		return core.Scope{}, errTargetNotFound
	}

	req := makeRequest(t, http.MethodGet, "/test", nil, userCtx, cs)
	rec := httptest.NewRecorder()
	handleScopedPermissionRequest(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), rec, req, "secrets.read", resolver)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "NotFound")
}

// TestHandleScopedPermission_NotFoundWithoutPermission verifies 403 when the
// resolver returns errTargetNotFound but the user does NOT hold global permission.
func TestHandleScopedPermission_NotFoundWithoutPermission(t *testing.T) {
	db := newScopedTestDB(t)
	// User with no roles at all.
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "nobody", AccountState: "active"}).Error)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	userCtx := &UserContext{UserID: 3, ActorType: core.ActorTypeUser}

	resolver := func(_ *http.Request, _ *core.KeyorixCore) (core.Scope, error) {
		return core.Scope{}, errTargetNotFound
	}

	req := makeRequest(t, http.MethodGet, "/test", nil, userCtx, cs)
	rec := httptest.NewRecorder()
	handleScopedPermissionRequest(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), rec, req, "secrets.read", resolver)

	// 403, not 404 — existence must not be revealed to unprivileged callers.
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestHandleScopedPermission_BadRequest verifies 400 when the resolver returns
// errInvalidTarget (non-"target not found" error).
func TestHandleScopedPermission_BadRequest(t *testing.T) {
	db := newScopedTestDB(t)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", AccountState: "active"}).Error)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	userCtx := &UserContext{UserID: 1, ActorType: core.ActorTypeUser}

	resolver := func(_ *http.Request, _ *core.KeyorixCore) (core.Scope, error) {
		return core.Scope{}, errInvalidTarget
	}

	req := makeRequest(t, http.MethodGet, "/test", nil, userCtx, cs)
	rec := httptest.NewRecorder()
	handleScopedPermissionRequest(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), rec, req, "secrets.read", resolver)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleScopedPermission_ProjectMFABlocked verifies 403 ProjectMFARequired
// when the user is an interactive session without MFA and the project requires MFA.
func TestHandleScopedPermission_ProjectMFABlocked(t *testing.T) {
	db := newScopedTestDB(t)
	seedAdmin(t, db, 1)
	require.NoError(t, db.Create(&models.Project{ID: 5, Name: "mfa-required", RequireMFA: true}).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	// SessionAuth=true, MFAEnabled=false → triggers the per-project MFA gate.
	userCtx := &UserContext{UserID: 1, ActorType: core.ActorTypeUser, SessionAuth: true, MFAEnabled: false}

	resolver := func(_ *http.Request, _ *core.KeyorixCore) (core.Scope, error) {
		return core.Scope{ProjectID: 5}, nil
	}

	req := makeRequest(t, http.MethodGet, "/test", nil, userCtx, cs)
	rec := httptest.NewRecorder()
	handleScopedPermissionRequest(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), rec, req, "secrets.read", resolver)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "ProjectMFARequired")
}

// --- ScopeFromEnvParam ---

// TestScopeFromEnvParam_Valid verifies the resolver loads the environment by ID
// and returns the correct project/environment scope.
func TestScopeFromEnvParam_Valid(t *testing.T) {
	db := newScopedTestDB(t)
	require.NoError(t, db.Create(&models.Project{ID: 3, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 20, ProjectID: 3, Name: "staging"}).Error)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))

	req := makeRequest(t, http.MethodGet, "/envs/20", map[string]string{"envId": "20"}, nil, nil)
	scope, err := ScopeFromEnvParam("envId")(req, cs)
	require.NoError(t, err)
	assert.Equal(t, uint(3), scope.ProjectID)
	assert.Equal(t, uint(20), scope.EnvironmentID)
}

// TestScopeFromEnvParam_InvalidParam verifies errInvalidTarget for a non-numeric param.
func TestScopeFromEnvParam_InvalidParam(t *testing.T) {
	req := makeRequest(t, http.MethodGet, "/envs/abc", map[string]string{"envId": "abc"}, nil, nil)
	_, err := ScopeFromEnvParam("envId")(req, nil)
	assert.Error(t, err)
}

// TestScopeFromEnvParam_NotFound verifies errTargetNotFound when no environment exists.
func TestScopeFromEnvParam_NotFound(t *testing.T) {
	db := newScopedTestDB(t)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))

	req := makeRequest(t, http.MethodGet, "/envs/999", map[string]string{"envId": "999"}, nil, nil)
	_, err := ScopeFromEnvParam("envId")(req, cs)
	assert.Error(t, err)
}

// --- ScopeFromSecretParam ---

// TestScopeFromSecretParam_Valid verifies the resolver loads the secret by ID and
// returns the correct project/environment scope.
func TestScopeFromSecretParam_Valid(t *testing.T) {
	db := newScopedTestDB(t)
	require.NoError(t, db.Create(&models.SecretNode{ID: 7, ProjectID: 4, EnvironmentID: 11, Name: "KEY"}).Error)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))

	req := makeRequest(t, http.MethodGet, "/secrets/7", map[string]string{"secretId": "7"}, nil, nil)
	scope, err := ScopeFromSecretParam("secretId")(req, cs)
	require.NoError(t, err)
	assert.Equal(t, uint(4), scope.ProjectID)
	assert.Equal(t, uint(11), scope.EnvironmentID)
}

// TestScopeFromSecretParam_InvalidParam verifies errInvalidTarget for non-numeric.
func TestScopeFromSecretParam_InvalidParam(t *testing.T) {
	req := makeRequest(t, http.MethodGet, "/secrets/xyz", map[string]string{"secretId": "xyz"}, nil, nil)
	_, err := ScopeFromSecretParam("secretId")(req, nil)
	assert.Error(t, err)
}

// TestScopeFromSecretParam_NotFound verifies errTargetNotFound when the secret row is absent.
func TestScopeFromSecretParam_NotFound(t *testing.T) {
	db := newScopedTestDB(t)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))

	req := makeRequest(t, http.MethodGet, "/secrets/999", map[string]string{"secretId": "999"}, nil, nil)
	_, err := ScopeFromSecretParam("secretId")(req, cs)
	assert.Error(t, err)
}

// --- ScopeFromDeletedSecretParam ---

// TestScopeFromDeletedSecretParam_Valid verifies that a soft-deleted secret can
// be located (Unscoped) and its scope returned.
func TestScopeFromDeletedSecretParam_Valid(t *testing.T) {
	db := newScopedTestDB(t)
	// Insert and immediately soft-delete the secret so it only exists in the
	// "including deleted" path.
	secret := &models.SecretNode{ID: 15, ProjectID: 6, EnvironmentID: 30, Name: "DELETED_KEY"}
	require.NoError(t, db.Create(secret).Error)
	require.NoError(t, db.Delete(secret).Error)

	cs := core.NewKeyorixCore(store.NewLocalStorage(db))
	req := makeRequest(t, http.MethodGet, "/secrets/15/restore", map[string]string{"secretId": "15"}, nil, nil)
	scope, err := ScopeFromDeletedSecretParam("secretId")(req, cs)
	require.NoError(t, err)
	assert.Equal(t, uint(6), scope.ProjectID)
	assert.Equal(t, uint(30), scope.EnvironmentID)
}

// TestScopeFromDeletedSecretParam_InvalidParam verifies errInvalidTarget for non-numeric.
func TestScopeFromDeletedSecretParam_InvalidParam(t *testing.T) {
	req := makeRequest(t, http.MethodGet, "/secrets/bad/restore", map[string]string{"secretId": "bad"}, nil, nil)
	_, err := ScopeFromDeletedSecretParam("secretId")(req, nil)
	assert.Error(t, err)
}

// TestScopeFromDeletedSecretParam_NotFound verifies errTargetNotFound when neither
// live nor deleted secret exists.
func TestScopeFromDeletedSecretParam_NotFound(t *testing.T) {
	db := newScopedTestDB(t)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))

	req := makeRequest(t, http.MethodGet, "/secrets/999/restore", map[string]string{"secretId": "999"}, nil, nil)
	_, err := ScopeFromDeletedSecretParam("secretId")(req, cs)
	assert.Error(t, err)
}

// --- ScopeFromShareParam ---

// TestScopeFromShareParam_Valid verifies the resolver follows the share → secret
// chain and returns the secret's project/environment scope.
func TestScopeFromShareParam_Valid(t *testing.T) {
	db := newScopedTestDB(t)
	require.NoError(t, db.Create(&models.SecretNode{ID: 8, ProjectID: 7, EnvironmentID: 40, Name: "SHARE_KEY"}).Error)
	require.NoError(t, db.Create(&models.ShareRecord{ID: 50, SecretID: 8, OwnerID: 1}).Error)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))

	req := makeRequest(t, http.MethodGet, "/shares/50", map[string]string{"shareId": "50"}, nil, nil)
	scope, err := ScopeFromShareParam("shareId")(req, cs)
	require.NoError(t, err)
	assert.Equal(t, uint(7), scope.ProjectID)
	assert.Equal(t, uint(40), scope.EnvironmentID)
}

// TestScopeFromShareParam_InvalidParam verifies errInvalidTarget for non-numeric.
func TestScopeFromShareParam_InvalidParam(t *testing.T) {
	req := makeRequest(t, http.MethodGet, "/shares/bad", map[string]string{"shareId": "bad"}, nil, nil)
	_, err := ScopeFromShareParam("shareId")(req, nil)
	assert.Error(t, err)
}

// TestScopeFromShareParam_ShareNotFound verifies errTargetNotFound when the share
// record does not exist.
func TestScopeFromShareParam_ShareNotFound(t *testing.T) {
	db := newScopedTestDB(t)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))

	req := makeRequest(t, http.MethodGet, "/shares/999", map[string]string{"shareId": "999"}, nil, nil)
	_, err := ScopeFromShareParam("shareId")(req, cs)
	assert.Error(t, err)
}

// TestScopeFromShareParam_SecretNotFound verifies errTargetNotFound when the share
// exists but its backing secret has been fully deleted.
func TestScopeFromShareParam_SecretNotFound(t *testing.T) {
	db := newScopedTestDB(t)
	// Share points to secret ID 99 which was never inserted.
	require.NoError(t, db.Create(&models.ShareRecord{ID: 60, SecretID: 99, OwnerID: 1}).Error)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))

	req := makeRequest(t, http.MethodGet, "/shares/60", map[string]string{"shareId": "60"}, nil, nil)
	_, err := ScopeFromShareParam("shareId")(req, cs)
	assert.Error(t, err)
}

// --- ScopeFromRotationPolicyParam ---

// TestScopeFromRotationPolicyParam_Valid verifies the resolver returns the policy's
// project/environment scope.
func TestScopeFromRotationPolicyParam_Valid(t *testing.T) {
	db := newScopedTestDB(t)
	projID := uint(9)
	envID := uint(55)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID:            100,
		Name:          "policy",
		Scope:         "environment",
		ProjectID:     &projID,
		EnvironmentID: &envID,
		IntervalDays:  30,
		CreatedBy:     "admin",
	}).Error)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))

	req := makeRequest(t, http.MethodGet, "/rotation-policies/100", map[string]string{"policyId": "100"}, nil, nil)
	scope, err := ScopeFromRotationPolicyParam("policyId")(req, cs)
	require.NoError(t, err)
	assert.Equal(t, uint(9), scope.ProjectID)
	assert.Equal(t, uint(55), scope.EnvironmentID)
}

// TestScopeFromRotationPolicyParam_NilPointers verifies that nil ProjectID /
// EnvironmentID on the policy map to 0 (global scope) without a panic.
func TestScopeFromRotationPolicyParam_NilPointers(t *testing.T) {
	db := newScopedTestDB(t)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID:           200,
		Name:         "global-policy",
		Scope:        "project",
		IntervalDays: 7,
		CreatedBy:    "admin",
	}).Error)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))

	req := makeRequest(t, http.MethodGet, "/rotation-policies/200", map[string]string{"policyId": "200"}, nil, nil)
	scope, err := ScopeFromRotationPolicyParam("policyId")(req, cs)
	require.NoError(t, err)
	assert.Equal(t, uint(0), scope.ProjectID)
	assert.Equal(t, uint(0), scope.EnvironmentID)
}

// TestScopeFromRotationPolicyParam_InvalidParam verifies errInvalidTarget.
func TestScopeFromRotationPolicyParam_InvalidParam(t *testing.T) {
	req := makeRequest(t, http.MethodGet, "/rotation-policies/abc", map[string]string{"policyId": "abc"}, nil, nil)
	_, err := ScopeFromRotationPolicyParam("policyId")(req, nil)
	assert.Error(t, err)
}

// TestScopeFromRotationPolicyParam_NotFound verifies errTargetNotFound.
func TestScopeFromRotationPolicyParam_NotFound(t *testing.T) {
	db := newScopedTestDB(t)
	cs := core.NewKeyorixCore(store.NewLocalStorage(db))

	req := makeRequest(t, http.MethodGet, "/rotation-policies/999", map[string]string{"policyId": "999"}, nil, nil)
	_, err := ScopeFromRotationPolicyParam("policyId")(req, cs)
	assert.Error(t, err)
}
