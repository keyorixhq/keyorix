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
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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

// #181: a viewer must get the identical response (status + body) whether the referenced
// secret doesn't exist or exists but they can't read it — otherwise the render endpoint
// is a 404-vs-403 existence oracle for secret names.
func TestRenderTemplate_UniformResponseForNotFoundVsForbidden(t *testing.T) {
	handler, projectID := setupRenderHandlerTest(t)

	doRender := func(template string) (int, string) {
		body, err := json.Marshal(map[string]string{"template": template})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/render", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withUserCtxID(req, 2, "viewer") // user 2: no ownership, no share
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

	require.Equal(t, http.StatusNotFound, forbiddenCode, "an existing-but-forbidden secret must not be distinguishable from a nonexistent one via status code")
	require.Equal(t, http.StatusNotFound, notFoundCode)
	require.Equal(t, notFoundBody, forbiddenBody, "response body must be identical for the nonexistent and forbidden cases")
}
