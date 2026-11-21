package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// TestBulkProjectSecretOps_MachineActorIsForbidden is #4514 (authzdiff known-10): a
// machine actor passes the router's secrets.write gate on bulk-rename, suspend-all
// and resume-all, but core takes a user ID and the machine's is 0. Core used to
// refuse with an untyped "actor ID is required", which REST answered 400 or 500; it
// now refuses as a machine actor (ErrPermissionDenied) and REST answers 403, with
// nothing changed.
func TestBulkProjectSecretOps_MachineActorIsForbidden(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{},
		&models.AuditEvent{}, &models.SecretAccessLog{}, &models.User{}, &models.Role{}, &models.UserRole{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p1"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, Name: "production", ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 5, Name: "db-password", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1,
		IsSecret: true, Status: "active", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}).Error)

	h, err := NewSecretHandler(core.NewKeyorixCore(store.NewLocalStorage(db)))
	require.NoError(t, err)

	asMachine := func(r *http.Request) *http.Request {
		uc := &customMiddleware.UserContext{UserID: 0, Username: "ci-bot", ActorType: core.ActorTypeMachine}
		ctx := context.WithValue(core.WithActorType(r.Context(), core.ActorTypeMachine), customMiddleware.GetUserContextKey(), uc)
		return withChiParam(r.WithContext(ctx), "id", "1")
	}
	for name, call := range map[string]func(http.ResponseWriter, *http.Request){
		"bulk-rename": h.BulkRenameSecrets,
		"suspend-all": h.SuspendProjectSecrets,
		"resume-all":  h.ResumeProjectSecrets,
	} {
		t.Run(name, func(t *testing.T) {
			body := `{"renames":[{"id":5,"new_name":"DB_PASSWORD"}],"reason":"incident"}`
			req := asMachine(httptest.NewRequest(http.MethodPost, "/api/v1/projects/1/secrets/"+name, strings.NewReader(body)))
			w := httptest.NewRecorder()
			call(w, req)
			require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
		})
	}

	var s models.SecretNode
	require.NoError(t, db.First(&s, 5).Error)
	require.Equal(t, "db-password", s.Name, "nothing was renamed")
	require.Equal(t, "active", s.Status, "nothing was suspended")
}
