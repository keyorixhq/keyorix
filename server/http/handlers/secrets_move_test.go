// secrets_move_test.go — HTTP-level tests for POST /api/v1/secrets/{id}/move.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// moveFixtureResult carries the created IDs for move handler tests.
type moveFixtureResult struct {
	handler  *SecretHandler
	secretID uint
	folderID uint
}

// freshMoveFixture opens a unique in-memory SQLite DB with all required models,
// seeds user 1 (owner), a project, an environment, one secret and one folder.
func freshMoveFixture(t *testing.T) moveFixtureResult {
	t.Helper()

	cfg := &config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}
	require.NoError(t, i18n.Initialize(cfg))

	n := s12DBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_move_%d?mode=memory&cache=shared&_timeout=30000", n)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Permission{},
		&models.RolePermission{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{},
		&models.AuditEvent{}, &models.SecretAccessLog{}, &models.ShareRecord{},
		&models.Tag{}, &models.SecretTag{},
		&models.ProjectMembership{}, &models.SoDPolicy{},
		&models.AnomalyAlert{}, &models.RotationPolicy{}, &models.Notification{},
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
		&models.LegalHold{},
		&models.PersonalAccessToken{},
		&models.ProjectInvitation{}, &models.SchedulerLockLease{},
		&models.SystemMetadata{},
		&models.PasswordHistory{},
	))

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner_move", Email: "owner_move@test.com"}).Error)

	st := store.NewLocalStorage(db)
	cs := core.NewKeyorixCore(st)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "proj-move"})
	require.NoError(t, err)
	// User 1 must be a project member so CheckSecretPermission's IsProjectMember gate passes.
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 1, ProjectID: proj.ID}).Error)
	env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "env-move", ProjectID: proj.ID})
	require.NoError(t, err)

	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name:          "db-password-move",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		Type:          "password",
		OwnerID:       1,
		IsSecret:      true,
		Status:        "active",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})
	require.NoError(t, err)

	folder, err := st.CreateSecret(ctx, &models.SecretNode{
		Name:          "infra-folder-move",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		Type:          "folder",
		OwnerID:       1,
		IsSecret:      false,
		Status:        "active",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})
	require.NoError(t, err)

	handler, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return moveFixtureResult{handler: handler, secretID: secret.ID, folderID: folder.ID}
}

// withMoveUserCtx injects user 1 into the request context.
func withMoveUserCtx(r *http.Request) *http.Request {
	uctx := &customMiddleware.UserContext{UserID: 1, Username: "owner_move", Email: "owner_move@test.com"}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), uctx))
}

// TestMoveSecret_HappyPath_ToFolder_HTTP verifies a successful move into a folder.
func TestMoveSecret_HappyPath_ToFolder_HTTP(t *testing.T) {
	fx := freshMoveFixture(t)

	body, _ := json.Marshal(map[string]uint{"parent_id": fx.folderID})
	req := withChiParamS14(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		"id", strconv.Itoa(int(fx.secretID)),
	)
	req = withMoveUserCtx(req)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	fx.handler.MoveSecret(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "moved")
}

// TestMoveSecret_ToRoot_HTTP verifies a successful move to root (parent_id=0).
func TestMoveSecret_ToRoot_HTTP(t *testing.T) {
	fx := freshMoveFixture(t)

	body, _ := json.Marshal(map[string]uint{"parent_id": 0})
	req := withChiParamS14(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		"id", strconv.Itoa(int(fx.secretID)),
	)
	req = withMoveUserCtx(req)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	fx.handler.MoveSecret(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestMoveSecret_NotFound_HTTP verifies a 404 for a non-existent secret.
func TestMoveSecret_NotFound_HTTP(t *testing.T) {
	fx := freshMoveFixture(t)

	body, _ := json.Marshal(map[string]uint{"parent_id": 0})
	req := withChiParamS14(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		"id", "99999",
	)
	req = withMoveUserCtx(req)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	fx.handler.MoveSecret(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestMoveSecret_NonFolderParent_HTTP verifies a 400 when target is not a folder.
func TestMoveSecret_NonFolderParent_HTTP(t *testing.T) {
	fx := freshMoveFixture(t)

	// Use the secret's own ID as target (IsSecret=true → not a folder, and also self).
	body, _ := json.Marshal(map[string]uint{"parent_id": fx.secretID})
	req := withChiParamS14(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		"id", strconv.Itoa(int(fx.secretID)),
	)
	req = withMoveUserCtx(req)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	fx.handler.MoveSecret(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestMoveSecret_InvalidID_HTTP verifies a 400 for a non-numeric secret ID.
func TestMoveSecret_InvalidID_HTTP(t *testing.T) {
	fx := freshMoveFixture(t)

	body, _ := json.Marshal(map[string]uint{"parent_id": 0})
	req := withChiParamS14(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		"id", "notanumber",
	)
	req = withMoveUserCtx(req)

	w := httptest.NewRecorder()
	fx.handler.MoveSecret(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestMoveSecret_InvalidJSON_HTTP verifies a 400 for malformed JSON.
func TestMoveSecret_InvalidJSON_HTTP(t *testing.T) {
	fx := freshMoveFixture(t)

	req := withChiParamS14(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("{bad json"))),
		"id", strconv.Itoa(int(fx.secretID)),
	)
	req = withMoveUserCtx(req)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	fx.handler.MoveSecret(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestMoveSecret_NoUserCtx_HTTP verifies a 401 when no user context is present.
func TestMoveSecret_NoUserCtx_HTTP(t *testing.T) {
	fx := freshMoveFixture(t)

	body, _ := json.Marshal(map[string]uint{"parent_id": 0})
	req := withChiParamS14(
		httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body)),
		"id", strconv.Itoa(int(fx.secretID)),
	)
	// No user context injected.

	w := httptest.NewRecorder()
	fx.handler.MoveSecret(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
