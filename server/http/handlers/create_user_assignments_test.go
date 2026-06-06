package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
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

func setupCreateUserAssignmentsTest(t *testing.T) (*UserHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.UserRole{}, &models.Role{}, &models.Project{}))
	require.NoError(t, db.Create(&models.Role{Name: "system_viewer"}).Error)
	require.NoError(t, db.Create(&models.Role{Name: "project_developer"}).Error)
	require.NoError(t, db.Create(&models.Project{Name: "default"}).Error)
	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	uh, err := NewUserHandler(coreService)
	require.NoError(t, err)
	return uh, db
}

func postCreateUser(t *testing.T, h *UserHandler, jsonBody string) *httptest.ResponseRecorder {
	t.Helper()
	req := withUserCtx(httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewReader([]byte(jsonBody))))
	w := httptest.NewRecorder()
	h.CreateUser(w, req)
	return w
}

func TestCreateUser_AtomicAssignments(t *testing.T) {
	h, db := setupCreateUserAssignmentsTest(t)
	var proj models.Project
	require.NoError(t, db.Where("name = ?", "default").First(&proj).Error)

	t.Run("creates the user with system + project role grants", func(t *testing.T) {
		body := `{"username":"provisioned","email":"prov@x.io","display_name":"Prov","password":"Str0ng#Pass!word","role":"system_viewer","project_assignments":[{"project_id":` + itoa(proj.ID) + `,"role":"project_developer"}]}`
		w := postCreateUser(t, h, body)
		require.Equal(t, http.StatusCreated, w.Code)

		var u models.User
		require.NoError(t, db.Where("username = ?", "provisioned").First(&u).Error)
		var roles []models.UserRole
		require.NoError(t, db.Where("user_id = ?", u.ID).Find(&roles).Error)
		require.Len(t, roles, 2)
		// One global (system_viewer) + one at the project scope.
		var globals, scoped int
		for _, r := range roles {
			if r.ProjectID == 0 {
				globals++
			} else if r.ProjectID == proj.ID {
				scoped++
			}
		}
		assert.Equal(t, 1, globals)
		assert.Equal(t, 1, scoped)
	})

	t.Run("an unknown project rejects with 400 and creates no user", func(t *testing.T) {
		body := `{"username":"badproj","email":"badproj@x.io","display_name":"Bad","password":"Str0ng#Pass!word","project_assignments":[{"project_id":9999,"role":"project_developer"}]}`
		w := postCreateUser(t, h, body)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		var n int64
		require.NoError(t, db.Model(&models.User{}).Where("username = ?", "badproj").Count(&n).Error)
		assert.Equal(t, int64(0), n)
	})

	t.Run("an unknown project role rejects with 400", func(t *testing.T) {
		body := `{"username":"badrole","email":"badrole@x.io","display_name":"Bad","password":"Str0ng#Pass!word","project_assignments":[{"project_id":` + itoa(proj.ID) + `,"role":"nope"}]}`
		w := postCreateUser(t, h, body)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("an unknown system role rejects with 400", func(t *testing.T) {
		body := `{"username":"badsys","email":"badsys@x.io","display_name":"Bad","password":"Str0ng#Pass!word","role":"nonexistent_role"}`
		w := postCreateUser(t, h, body)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("assignments combined with a setup link are rejected", func(t *testing.T) {
		body := `{"username":"mix","email":"mix@x.io","display_name":"Mix","role":"system_viewer","deliver_setup_link":true}`
		w := postCreateUser(t, h, body)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
