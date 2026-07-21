package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupRotationStateTest(t *testing.T) (*RotationPolicyHandler, *gorm.DB) {
	t.Helper()

	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	require.NoError(t, i18n.Initialize(cfg))

	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, db.AutoMigrate(
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.RotationPolicy{},
		&models.Role{},
		&models.Permission{},
		&models.RolePermission{},
		&models.UserRole{},
		&models.Group{},
		&models.UserGroup{},
		&models.GroupRole{},
	))

	// Make the test user (ID 1) a global admin so scoped permission checks pass.
	adminRole := &models.Role{Name: "admin", Description: "Administrator"}
	require.NoError(t, db.Create(adminRole).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: adminRole.ID}).Error)

	localStorage := store.NewLocalStorage(db)
	coreService := core.NewKeyorixCore(localStorage)
	handler := NewRotationPolicyHandler(coreService)
	return handler, db
}

// seedRotationStateFixtures creates a project, environment, secret, and an active
// rotation policy scoped to that project. Returns the secret ID and policy ID.
func seedRotationStateFixtures(t *testing.T, db *gorm.DB) (secretID uint, policyID uint) {
	t.Helper()
	proj := &models.Project{Name: "rot-state-proj"}
	require.NoError(t, db.Create(proj).Error)

	env := &models.Environment{Name: "prod", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)

	secret := &models.SecretNode{
		Name:          "MY_SECRET",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		IsSecret:      true,
	}
	require.NoError(t, db.Create(secret).Error)

	policy := &models.RotationPolicy{
		Name:         "30-day policy",
		Scope:        "project",
		ProjectID:    &proj.ID,
		IntervalDays: 30,
		IsActive:     true,
		CreatedBy:    "testuser",
	}
	require.NoError(t, db.Create(policy).Error)
	return secret.ID, policy.ID
}

// TestGetRotationState_200_WithPolicy verifies that a secret with an active policy
// returns HTTP 200 with the policy state fields.
func TestGetRotationState_200_WithPolicy(t *testing.T) {
	handler, db := setupRotationStateTest(t)
	secretID, _ := seedRotationStateFixtures(t, db)

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d/rotation-state", secretID), nil)
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", secretID)))

	w := httptest.NewRecorder()
	handler.GetRotationState(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"state"`)
	assert.Contains(t, body, `"secret_id"`)
}

// TestGetRotationState_200_NoPolicy verifies that a secret with no active policy
// returns HTTP 200 with state="idle" (no 404).
func TestGetRotationState_200_NoPolicy(t *testing.T) {
	handler, db := setupRotationStateTest(t)

	// Create a secret in a project that has no rotation policy.
	proj := &models.Project{Name: "no-policy-proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "staging", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	secret := &models.SecretNode{
		Name:          "BARE_SECRET",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		IsSecret:      true,
	}
	require.NoError(t, db.Create(secret).Error)

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d/rotation-state", secret.ID), nil)
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", secret.ID)))

	w := httptest.NewRecorder()
	handler.GetRotationState(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"idle"`)
}

// TestGetRotationState_400_BadID verifies that a non-numeric secret ID returns 400.
func TestGetRotationState_400_BadID(t *testing.T) {
	handler, _ := setupRotationStateTest(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/abc/rotation-state", nil)
	req = withUserCtx(withChiParam(req, "id", "abc"))

	w := httptest.NewRecorder()
	handler.GetRotationState(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestGetRotationState_401_NoUser verifies that a missing user context returns 401.
func TestGetRotationState_401_NoUser(t *testing.T) {
	handler, _ := setupRotationStateTest(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1/rotation-state", nil)
	// No withUserCtx — user context is absent.
	req = withChiParam(req, "id", "1")

	w := httptest.NewRecorder()
	handler.GetRotationState(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGetRotationState_StateAfterStamp verifies that after SetRotationState is called
// the GET endpoint reflects the updated state.
func TestGetRotationState_StateAfterStamp(t *testing.T) {
	handler, db := setupRotationStateTest(t)
	secretID, policyID := seedRotationStateFixtures(t, db)

	// Stamp the policy via the store directly (simulating the rotation executor).
	localStorage := store.NewLocalStorage(db)
	err := localStorage.UpdateRotationState(context.Background(), policyID, core.RotationStateFailed, "backend timeout")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/secrets/%d/rotation-state", secretID), nil)
	req = withUserCtx(withChiParam(req, "id", fmt.Sprintf("%d", secretID)))

	w := httptest.NewRecorder()
	handler.GetRotationState(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.True(t, strings.Contains(body, `"failed"`) || strings.Contains(body, `"backend timeout"`),
		"expected failed state or error message in response: %s", body)
}
