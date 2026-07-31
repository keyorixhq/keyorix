package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
)

func setupUserEnhancementTest(t *testing.T) (*UserHandler, *UsersRolesHandler, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.ProjectMembership{}, &models.Project{}))
	coreService := core.NewKeyorixCore(store.NewLocalStorage(db))
	uh, err := NewUserHandler(coreService)
	require.NoError(t, err)
	return uh, NewUsersRolesHandler(coreService), db
}

func decodeData(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok, "response has a data object")
	return data
}

func TestStaleAccountsHandler(t *testing.T) {
	uh, _, db := setupUserEnhancementTest(t)

	// One stale pending account (>7d), one recent pending, one active old.
	mk := func(name, state string, age time.Duration) {
		require.NoError(t, db.Create(&models.User{Username: name, Email: name + "@x.com", AccountState: state}).Error)
		require.NoError(t, db.Model(&models.User{}).Where("username = ?", name).
			UpdateColumn("created_at", time.Now().Add(-age)).Error)
	}
	mk("stale-bot", core.AccountPendingFirstLogin, 10*24*time.Hour)
	mk("fresh-bot", core.AccountPendingFirstLogin, 1*24*time.Hour)
	mk("old-active", core.AccountActive, 30*24*time.Hour)

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/stale?days=7", nil))
	w := httptest.NewRecorder()
	uh.StaleAccounts(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	data := decodeData(t, w)
	users := data["users"].([]interface{})
	require.Len(t, users, 1, "only the >7d pending account")
	assert.Equal(t, "stale-bot", users[0].(map[string]interface{})["username"])
	assert.Equal(t, core.AccountPendingFirstLogin, data["state"])

	// Unsupported state is a 400.
	bad := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/stale?state=active", nil))
	bw := httptest.NewRecorder()
	uh.StaleAccounts(bw, bad)
	assert.Equal(t, http.StatusBadRequest, bw.Code)
}

func TestListUsers_MergesProjectCounts(t *testing.T) {
	uh, _, db := setupUserEnhancementTest(t)

	require.NoError(t, db.Create(&models.User{Username: "alice", Email: "alice@x.com", AccountState: core.AccountActive}).Error)
	var alice models.User
	require.NoError(t, db.Where("username = ?", "alice").First(&alice).Error)
	// 2 active + 1 revoked → active 2, total 2 (revoked excluded).
	for _, st := range []string{"active", "active", "revoked"} {
		require.NoError(t, db.Create(&models.ProjectMembership{ProjectID: 1, UserID: alice.ID, State: st}).Error)
	}

	req := withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users", nil))
	w := httptest.NewRecorder()
	uh.ListUsers(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	data := decodeData(t, w)
	users := data["users"].([]interface{})
	require.Len(t, users, 1)
	u := users[0].(map[string]interface{})
	assert.Equal(t, float64(2), u["active_project_count"])
	assert.Equal(t, float64(2), u["project_count"])
}

func TestGetUserMembershipsHandler(t *testing.T) {
	_, rh, db := setupUserEnhancementTest(t)

	require.NoError(t, db.Create(&models.Project{Name: "payments"}).Error)
	var proj models.Project
	require.NoError(t, db.Where("name = ?", "payments").First(&proj).Error)
	require.NoError(t, db.Create(&models.ProjectMembership{ProjectID: proj.ID, UserID: 42, Role: "project_developer", State: "active"}).Error)

	req := withChiParam(withUserCtx(httptest.NewRequest(http.MethodGet, "/api/v1/users/42/memberships", nil)), "id", "42")
	w := httptest.NewRecorder()
	rh.GetUserMembershipsForUser(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	data := decodeData(t, w)
	memberships := data["memberships"].([]interface{})
	require.Len(t, memberships, 1)
	m := memberships[0].(map[string]interface{})
	assert.Equal(t, "payments", m["project_name"])
	assert.Equal(t, "project_developer", m["role"])
	assert.Equal(t, "active", m["state"])
	assert.Equal(t, float64(proj.ID), m["project_id"])
}
