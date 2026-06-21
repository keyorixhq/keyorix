package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newMigrateHandler(t *testing.T) (*CatalogHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.MachineIdentity{}, &models.Project{}, &models.Session{}, &models.AuditEvent{},
	))
	require.NoError(t, db.Create(&models.Project{ID: 3, Name: "platform"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 7, Username: "ci-bot", Email: "ci-bot@x.io", AccountState: core.AccountActive}).Error)
	return NewCatalogHandler(core.NewKeyorixCore(store.NewLocalStorage(db))), db
}

func TestMigrateUserToMachineHandler(t *testing.T) {
	t.Run("creates the machine identity and suspends the source user by default", func(t *testing.T) {
		h, db := newMigrateHandler(t)
		req := withUserCtx(withChiParam(
			httptest.NewRequest(http.MethodPost, "/api/v1/projects/3/machine-identities/migrate-from-user",
				strings.NewReader(`{"username":"ci-bot"}`)), "id", "3"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.MigrateUserToMachine(w, req)

		require.Equal(t, http.StatusCreated, w.Code)
		var m models.MachineIdentity
		require.NoError(t, db.Where("project_id = ? AND name = ?", 3, "ci-bot").First(&m).Error)
		// Source user suspended (default — human login closed), never deleted.
		var u models.User
		require.NoError(t, db.First(&u, 7).Error)
		assert.Equal(t, core.AccountSuspended, u.AccountState)
	})

	t.Run("keep_user leaves the source account active", func(t *testing.T) {
		h, db := newMigrateHandler(t)
		req := withUserCtx(withChiParam(
			httptest.NewRequest(http.MethodPost, "/api/v1/projects/3/machine-identities/migrate-from-user",
				strings.NewReader(`{"username":"ci-bot","name":"ci","keep_user":true}`)), "id", "3"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.MigrateUserToMachine(w, req)

		require.Equal(t, http.StatusCreated, w.Code)
		var u models.User
		require.NoError(t, db.First(&u, 7).Error)
		assert.Equal(t, core.AccountActive, u.AccountState, "keep_user must not suspend")
	})

	t.Run("unknown user is a 404", func(t *testing.T) {
		h, _ := newMigrateHandler(t)
		req := withUserCtx(withChiParam(
			httptest.NewRequest(http.MethodPost, "/api/v1/projects/3/machine-identities/migrate-from-user",
				strings.NewReader(`{"username":"ghost"}`)), "id", "3"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.MigrateUserToMachine(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("missing username is a 400", func(t *testing.T) {
		h, _ := newMigrateHandler(t)
		req := withUserCtx(withChiParam(
			httptest.NewRequest(http.MethodPost, "/api/v1/projects/3/machine-identities/migrate-from-user",
				strings.NewReader(`{}`)), "id", "3"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.MigrateUserToMachine(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
