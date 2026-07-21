// secrets_retention_override_test.go — handler coverage for SetRetentionOverride.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var retentionOverrideDBCounter atomic.Int64

// freshRetentionHandlerFixture opens a unique in-memory SQLite DB, migrates
// models, seeds one user + project + env + secret, and returns the handler and
// the secret's ID.
func freshRetentionHandlerFixture(t *testing.T) (*SecretHandler, uint) {
	t.Helper()

	cfg := &config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}
	require.NoError(t, i18n.Initialize(cfg))

	n := retentionOverrideDBCounter.Add(1)
	dsn := fmt.Sprintf("file:kxhandlers_ret_%d?mode=memory&cache=shared&_timeout=30000", n)
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

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "retowner", Email: "retowner@test.com"}).Error)

	st := store.NewLocalStorage(db)
	cs := core.NewKeyorixCore(st)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "proj-ret"})
	require.NoError(t, err)
	env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "env-ret", ProjectID: proj.ID})
	require.NoError(t, err)
	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name:          "high-value-secret",
		ProjectID:     proj.ID,
		EnvironmentID: env.ID,
		Type:          "static",
		OwnerID:       1,
		IsSecret:      true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	})
	require.NoError(t, err)

	h, err := NewSecretHandler(cs)
	require.NoError(t, err)
	return h, secret.ID
}

// withRetentionUserCtx injects UserID=1 into the request context.
func withRetentionUserCtx(r *http.Request) *http.Request {
	uctx := &customMiddleware.UserContext{UserID: 1, Username: "retowner", Email: "retowner@test.com"}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), uctx))
}

// ── 401 — missing user context ────────────────────────────────────────────────

// TestSetRetentionOverride_NoUserCtx_401 verifies that a request without an
// authenticated user context returns 401.
func TestSetRetentionOverride_NoUserCtx_401(t *testing.T) {
	h, id := freshRetentionHandlerFixture(t)

	body, _ := json.Marshal(map[string]int{"retention_override_days": 30})
	req := withChiParamS14(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/"+strconv.Itoa(int(id))+"/retention", bytes.NewReader(body)),
		"id", strconv.Itoa(int(id)),
	)
	w := httptest.NewRecorder()
	h.SetRetentionOverride(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── 400 — bad secret ID ───────────────────────────────────────────────────────

// TestSetRetentionOverride_BadID_400 sends a non-numeric id path parameter → 400.
func TestSetRetentionOverride_BadID_400(t *testing.T) {
	h, _ := freshRetentionHandlerFixture(t)

	body, _ := json.Marshal(map[string]int{"retention_override_days": 30})
	req := withRetentionUserCtx(withChiParamS14(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/bad/retention", bytes.NewReader(body)),
		"id", "not-a-number",
	))
	w := httptest.NewRecorder()
	h.SetRetentionOverride(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── 400 — invalid JSON ────────────────────────────────────────────────────────

// TestSetRetentionOverride_InvalidJSON_400 sends a malformed body → 400.
func TestSetRetentionOverride_InvalidJSON_400(t *testing.T) {
	h, id := freshRetentionHandlerFixture(t)

	req := withRetentionUserCtx(withChiParamS14(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/"+strconv.Itoa(int(id))+"/retention",
			bytes.NewBufferString("{not-valid-json")),
		"id", strconv.Itoa(int(id)),
	))
	w := httptest.NewRecorder()
	h.SetRetentionOverride(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── 400 — below minimum (days=6) ─────────────────────────────────────────────

// TestSetRetentionOverride_BelowMin_400 sends retention_override_days=6 (below
// the 7-day floor) → core returns ErrInvalidRetentionDays → 400.
func TestSetRetentionOverride_BelowMin_400(t *testing.T) {
	h, id := freshRetentionHandlerFixture(t)

	body, _ := json.Marshal(map[string]int{"retention_override_days": 6})
	req := withRetentionUserCtx(withChiParamS14(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/"+strconv.Itoa(int(id))+"/retention", bytes.NewReader(body)),
		"id", strconv.Itoa(int(id)),
	))
	w := httptest.NewRecorder()
	h.SetRetentionOverride(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "ValidationError")
}

// ── 400 — negative days ───────────────────────────────────────────────────────

// TestSetRetentionOverride_Negative_400 sends retention_override_days=-1 → 400.
func TestSetRetentionOverride_Negative_400(t *testing.T) {
	h, id := freshRetentionHandlerFixture(t)

	body, _ := json.Marshal(map[string]int{"retention_override_days": -1})
	req := withRetentionUserCtx(withChiParamS14(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/"+strconv.Itoa(int(id))+"/retention", bytes.NewReader(body)),
		"id", strconv.Itoa(int(id)),
	))
	w := httptest.NewRecorder()
	h.SetRetentionOverride(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── 200 — valid override ──────────────────────────────────────────────────────

// TestSetRetentionOverride_Valid_200 sets a valid 30-day override → 200.
func TestSetRetentionOverride_Valid_200(t *testing.T) {
	h, id := freshRetentionHandlerFixture(t)

	body, _ := json.Marshal(map[string]int{"retention_override_days": 30})
	req := withRetentionUserCtx(withChiParamS14(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/"+strconv.Itoa(int(id))+"/retention", bytes.NewReader(body)),
		"id", strconv.Itoa(int(id)),
	))
	w := httptest.NewRecorder()
	h.SetRetentionOverride(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, true, resp["success"])
	data := resp["data"].(map[string]interface{})
	assert.Equal(t, float64(30), data["retention_override_days"])
}

// ── 200 — clear override (days=0) ────────────────────────────────────────────

// TestSetRetentionOverride_ClearOverride_200 sends days=0 to clear an override → 200.
func TestSetRetentionOverride_ClearOverride_200(t *testing.T) {
	h, id := freshRetentionHandlerFixture(t)

	body, _ := json.Marshal(map[string]int{"retention_override_days": 0})
	req := withRetentionUserCtx(withChiParamS14(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/"+strconv.Itoa(int(id))+"/retention", bytes.NewReader(body)),
		"id", strconv.Itoa(int(id)),
	))
	w := httptest.NewRecorder()
	h.SetRetentionOverride(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, true, resp["success"])
	data := resp["data"].(map[string]interface{})
	assert.Equal(t, float64(0), data["retention_override_days"])
}

// ── 200 — exact minimum (days=7) ─────────────────────────────────────────────

// TestSetRetentionOverride_ExactMin_200 sets exactly 7 days (the minimum) → 200.
func TestSetRetentionOverride_ExactMin_200(t *testing.T) {
	h, id := freshRetentionHandlerFixture(t)

	body, _ := json.Marshal(map[string]int{"retention_override_days": 7})
	req := withRetentionUserCtx(withChiParamS14(
		httptest.NewRequest(http.MethodPatch, "/api/v1/secrets/"+strconv.Itoa(int(id))+"/retention", bytes.NewReader(body)),
		"id", strconv.Itoa(int(id)),
	))
	w := httptest.NewRecorder()
	h.SetRetentionOverride(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
