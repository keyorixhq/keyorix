package handlers

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// AUTHZ-ORACLE-1 item 4 over REST: the loser of a POST /api/v1/users race on one
// username answers 409, like the sequential duplicate, on the plain path
// (CreateUser) and the atomic-assignments path (CreateUserWithRoleGrants). Before
// the fix its insert hit the users username unique index unmapped and answered 500.
func TestCreateUser_UsernameRaceLoserAnswers409(t *testing.T) {
	_, db := setupCreateUserAssignmentsTest(t)
	// The production partial index (migrateDatabase); AutoMigrate lacks it.
	require.NoError(t, db.Exec("UPDATE users SET username_folded = lower(username) WHERE username_folded = ''").Error)
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX uniq_users_username_folded_active ON users (username_folded) WHERE deleted_at IS NULL").Error)
	require.NoError(t, db.Create(&models.User{Username: "racer", UsernameFolded: "racer", Email: "winner@x.io", EmailFolded: "winner@x.io", IsActive: true}).Error)

	racing := core.NewKeyorixCore(storagetest.Hooked(store.NewLocalStorage(db), &storagetest.StoreHooks{
		WrapTx: true,
		GetUserByUsername: func(_ corestorage.Storage, _ context.Context, _ string) (*models.User, error) {
			return nil, fmt.Errorf("lookup: %w", corestorage.ErrUserNotFound) // the winner has not committed yet
		},
	}))
	h, err := NewUserHandler(racing)
	require.NoError(t, err)

	for name, body := range map[string]string{
		"plain":       `{"username":"racer","email":"loser1@x.io","display_name":"Loser","password":"Str0ng#Pass!word"}`,
		"assignments": `{"username":"racer","email":"loser2@x.io","display_name":"Loser","password":"Str0ng#Pass!word","role":"system_viewer"}`,
	} {
		w := postCreateUser(t, h, body)
		assert.Equal(t, http.StatusConflict, w.Code, "%s: %s", name, w.Body.String())
	}
}
