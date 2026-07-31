package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func setupUserHandlerTest(t *testing.T) *UserHandler {
	t.Helper()

	cfg := &config.Config{
		Locale: config.LocaleConfig{
			Language:         "en",
			FallbackLanguage: "en",
		},
	}
	require.NoError(t, i18n.Initialize(cfg))

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.Session{}, &models.AuditEvent{}))

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "admin@test.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "target", Email: "target@test.com"}).Error)

	storage := store.NewLocalStorage(db)
	coreService := core.NewKeyorixCore(storage)
	handler, err := NewUserHandler(coreService)
	require.NoError(t, err)
	return handler
}

// RevokeSessions previously had no guard against an admin targeting their own
// ID — unlike accountStateAction (Suspend/Reactivate/RequirePasswordReset),
// which explicitly blocks self-action. An admin could revoke their own active
// sessions out from under themselves mid-request.
func TestRevokeSessions_BlocksSelfAction(t *testing.T) {
	handler := setupUserHandlerTest(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/1/revoke-sessions", nil)
	req = withUserCtx(req) // admin, UserID: 1
	req = withChiParam(req, "id", "1")

	w := httptest.NewRecorder()
	handler.RevokeSessions(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "an admin must not be able to revoke their own sessions")
}

func TestRevokeSessions_AllowsTargetingOtherUsers(t *testing.T) {
	handler := setupUserHandlerTest(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/2/revoke-sessions", nil)
	req = withUserCtx(req) // admin, UserID: 1
	req = withChiParam(req, "id", "2")

	w := httptest.NewRecorder()
	handler.RevokeSessions(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "revoking another user's sessions must still work")
}
