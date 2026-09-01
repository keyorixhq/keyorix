package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// setupRenderHandlerTest builds a project with a "production" environment and a
// secret "db-password" owned by user 1, plus a second user (2) with no access to it.
func setupRenderHandlerTest(t *testing.T) (*SecretHandler, uint) {
	t.Helper()

	cfg := &config.Config{Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"}}
	require.NoError(t, i18n.Initialize(cfg))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{},
		&models.Project{}, &models.Environment{}, &models.SecretAccessLog{}, &models.AuditEvent{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@test.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "viewer", Email: "v@test.com"}).Error)

	st := store.NewLocalStorage(db)
	coreService := core.NewKeyorixCore(st)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "payments"})
	require.NoError(t, err)
	env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: proj.ID})
	require.NoError(t, err)
	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "db-password", ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password",
		OwnerID: 1, IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = st.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("s3cr3t"),
	})
	require.NoError(t, err)

	handler, err := NewSecretHandler(coreService)
	require.NoError(t, err)
	return handler, proj.ID
}

func withUserCtxID(r *http.Request, userID uint, username string) *http.Request {
	userCtx := &customMiddleware.UserContext{UserID: userID, Username: username, Email: username + "@test.com"}
	return r.WithContext(context.WithValue(r.Context(), customMiddleware.GetUserContextKey(), userCtx))
}

// #181/ADR-096: a viewer must get the identical response (status + body)
// whether the referenced secret doesn't exist or exists but they can't read
// it — otherwise the render endpoint is an existence oracle for secret names.
// The status the two cases collapse TO changed under ADR-096 (403-for-both,
// not 404-for-both): user 2 here holds no RBAC grant anywhere, not even
// globally, so both cases now deny as Forbidden — see
// TestRenderTemplate_GlobalPermissionRevealsRealNotFound below for the
// narrow exception that still yields a genuine 404.
func TestRenderTemplate_UniformResponseForNotFoundVsForbidden(t *testing.T) {
	handler, projectID := setupRenderHandlerTest(t)

	doRender := func(template string) (int, string) {
		body, err := json.Marshal(map[string]string{"template": template})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/render", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withUserCtxID(req, 2, "viewer") // user 2: no ownership, no share, no RBAC grant
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", strconv.FormatUint(uint64(projectID), 10))
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		w := httptest.NewRecorder()
		handler.RenderTemplate(w, req)
		return w.Code, w.Body.String()
	}

	// "db-password" exists (owned by user 1) but user 2 has no access to it.
	forbiddenCode, forbiddenBody := doRender("${secret:production/db-password}")
	// "nope" does not exist at all, in the same environment.
	notFoundCode, notFoundBody := doRender("${secret:production/nope}")

	require.Equal(t, http.StatusForbidden, forbiddenCode, "an existing-but-forbidden secret must not be distinguishable from a nonexistent one via status code")
	require.Equal(t, http.StatusForbidden, notFoundCode)
	require.Equal(t, notFoundBody, forbiddenBody, "response body must be identical for the nonexistent and forbidden cases")
}

// TestRenderTemplate_GlobalPermissionRevealsRealNotFound is the narrow
// ADR-096 exception: a caller who holds secrets.read at GLOBAL scope gets a
// genuine 404 for a reference that truly doesn't exist — distinct from the
// 403 the same caller would see for a reference they exist-but-can't-read
// (not exercised here; see TestSendRenderTemplateError_ErrSecretRefNotFound_*
// in handlers_s14_test.go for that side of the split).
func TestRenderTemplate_GlobalPermissionRevealsRealNotFound(t *testing.T) {
	handler, projectID := setupRenderHandlerTest(t)
	ctx := context.Background()
	st := handler.coreService.Storage()

	perm, err := st.CreatePermission(ctx, &models.Permission{Name: "secrets.read", Description: "read secrets"})
	require.NoError(t, err)
	folded, err := identity.NewFoldedName("global-render-reader-181")
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, folded, "global reader")
	require.NoError(t, err)
	require.NoError(t, st.AssignPermissionToRole(ctx, role.ID, perm.ID))
	require.NoError(t, st.AssignRole(ctx, 2, role.ID, core.Scope{})) // user 2, global

	body, err := json.Marshal(map[string]string{"template": "${secret:production/nope}"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/render", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUserCtxID(req, 2, "viewer")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", strconv.FormatUint(uint64(projectID), 10))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	handler.RenderTemplate(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
}
