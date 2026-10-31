package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// AUTHZ-ORACLE-TAILS-1 item 2 over HTTP. The loser of a race on one username answers
// 409 (REST, and SCIM with scimType "uniqueness") instead of a storage failure, and
// leaves nothing behind. The production partial index is created (AutoMigrate lacks
// it) and the loser's name pre-check is made to miss the winner's committed row.

const usernameIndexSQL = "CREATE UNIQUE INDEX uniq_users_username_folded_active ON users (username_folded) WHERE deleted_at IS NULL"

func missingUsernameStorage(db *gorm.DB) corestorage.Storage {
	return storagetest.Hooked(store.NewLocalStorage(db), &storagetest.StoreHooks{
		WrapTx: true,
		GetUserByUsername: func(_ corestorage.Storage, _ context.Context, _ string) (*models.User, error) {
			return nil, fmt.Errorf("lookup: %w", corestorage.ErrUserNotFound) // the winner has not committed yet
		},
	})
}

// PUT /api/v1/users/{id} renaming a user to a name a concurrent rename just took.
func TestUpdateUser_RenameRaceLoserAnswers409(t *testing.T) {
	_, db := setupCreateUserAssignmentsTest(t)
	require.NoError(t, db.Exec(usernameIndexSQL).Error)
	require.NoError(t, db.Create(&models.User{Username: "racer", UsernameFolded: "racer", Email: "winner@x.io", EmailFolded: "winner@x.io", IsActive: true}).Error)
	loser := &models.User{Username: "bob", UsernameFolded: "bob", Email: "bob@x.io", EmailFolded: "bob@x.io", IsActive: true, AccountState: core.AccountActive}
	require.NoError(t, db.Create(loser).Error)

	h, err := NewUserHandler(core.NewKeyorixCore(missingUsernameStorage(db)))
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]any{"username": "racer"})
	req := withUserCtx(withChiParam(
		httptest.NewRequest(http.MethodPut, "/api/v1/users/999", bytes.NewReader(body)),
		"id", itoa(loser.ID),
	))
	w := httptest.NewRecorder()
	h.UpdateUser(w, req)
	assert.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "username_folded", "the raw constraint text must not reach the caller")

	var got models.User
	require.NoError(t, db.First(&got, loser.ID).Error)
	assert.Equal(t, "bob", got.UsernameFolded, "the refused rename changed nothing")
	var n int64
	require.NoError(t, db.Model(&models.User{}).Where("username_folded = ?", "racer").Count(&n).Error)
	assert.Equal(t, int64(1), n)
}

// POST /scim/v2/Users whose derived username a concurrent provision just took: 409
// uniqueness, and no user row, no baseline grant (they commit together).
func TestSCIM_CreateUserUsernameRaceLoserAnswers409Uniqueness(t *testing.T) {
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Session{}, &models.PersonalAccessToken{}, &models.AuditEvent{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{}, &models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Exec(usernameIndexSQL).Error)
	require.NoError(t, db.Create(&models.Role{Name: "system_viewer"}).Error)
	require.NoError(t, db.Create(&models.User{Username: "racer", UsernameFolded: "racer", Email: "winner@corp.com", EmailFolded: "winner@corp.com", IsActive: true}).Error)
	var users, grants int64
	require.NoError(t, db.Unscoped().Model(&models.User{}).Count(&users).Error)
	require.NoError(t, db.Unscoped().Model(&models.UserRole{}).Count(&grants).Error)

	h := NewSCIMHandler(core.NewKeyorixCore(missingUsernameStorage(db)))
	w := httptest.NewRecorder()
	h.CreateUser(w, httptest.NewRequest(http.MethodPost, "/scim/v2/Users",
		bytes.NewReader([]byte(`{"userName":"racer@loser.corp.com","externalId":"idp-loser"}`))))
	body := assertSCIMErrorBody(t, w, http.StatusConflict)
	assert.Equal(t, "uniqueness", body["scimType"])

	var usersAfter, grantsAfter int64
	require.NoError(t, db.Unscoped().Model(&models.User{}).Count(&usersAfter).Error)
	require.NoError(t, db.Unscoped().Model(&models.UserRole{}).Count(&grantsAfter).Error)
	assert.Equal(t, users, usersAfter, "no user row left behind")
	assert.Equal(t, grants, grantsAfter, "no baseline grant left behind")
}

// classifySCIMError answers the typed sentinel itself as 409 uniqueness too, for any
// SCIM write path that lets it through unmapped.
func TestClassifySCIMError_DuplicateUsernameIs409Uniqueness(t *testing.T) {
	c := classifySCIMError(fmt.Errorf("write: %w", corestorage.ErrDuplicateUsername))
	assert.Equal(t, http.StatusConflict, c.status)
	assert.Equal(t, scimTypeUniqueness, c.scimType)
}
