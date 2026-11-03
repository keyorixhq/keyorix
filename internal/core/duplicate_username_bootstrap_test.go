package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// USERNAME-UNIQ-TAILS-1 item 2: first-admin bootstrap has no username pre-check, only
// the users username unique index, so a writer that commits the same folded username
// after the "no users yet" check (another replica creating a user outside the bootstrap
// lock) makes the admin insert hit the index. The caller must get the same "already
// exists" answer the email collision gets (ErrUserAlreadyExists), not a storage failure
// carrying the constraint text, and the single bootstrap transaction must leave nothing
// behind (no seeded permission or role, no admin grant, no initialised marker).
// Production schema, SQLite and Postgres.
func TestBootstrapSystem_UsernameRaceLoserAnswersAlreadyExistsAndSeedsNothing(t *testing.T) {
	productionSchemaBackends(t, func(t *testing.T, w *txClosureWorld) {
		ctx := context.Background()
		raced := false
		c := NewKeyorixCore(hooked(w.fs, &storeHooks{
			WrapTx: true,
			// The pre-transaction username check runs after the rival commits in real
			// life too, only on another replica's snapshot; blind it so the insert, not
			// the check, is what meets the rival (as TestCreateUser_UsernameRaceLoser...).
			GetUserByUsername: func(_ storage.Storage, _ context.Context, _ string) (*models.User, error) {
				return nil, fmt.Errorf("lookup: %w", storage.ErrUserNotFound)
			},
			ListUsers: func(next storage.Storage, ctx context.Context, f *storage.UserFilter) ([]*models.User, int64, error) {
				users, total, err := next.ListUsers(ctx, f)
				if err == nil && !raced {
					raced = true // the rival commits just after the empty-install check
					require.NoError(t, w.db.Create(&models.User{
						Username: "Admin", UsernameFolded: "admin", Email: "rival@example.com", EmailFolded: "rival@example.com",
						IsActive: true, AccountState: AccountActive,
					}).Error)
				}
				return users, total, err
			},
		}))
		c.SetBootstrapToken("test-bootstrap-token")

		_, err := c.BootstrapSystem(ctx, &BootstrapRequest{
			Username: "admin", Email: "admin@example.com", Password: "Kx7!Bootstrap-Pwd", DisplayName: "Administrator",
			Token: "test-bootstrap-token",
		})
		require.True(t, raced, "the rival write was never injected")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUserAlreadyExists, "the bootstrap loser must get the 'already exists' answer: %v", err)
		assert.NotContains(t, err.Error(), "username_folded", "the raw constraint text must not reach the caller")
		assert.NotContains(t, err.Error(), "Storage failed")

		var users, perms, roles, grants, marker int64
		require.NoError(t, w.db.Unscoped().Model(&models.User{}).Count(&users).Error)
		require.NoError(t, w.db.Unscoped().Model(&models.Permission{}).Count(&perms).Error)
		require.NoError(t, w.db.Unscoped().Model(&models.Role{}).Count(&roles).Error)
		require.NoError(t, w.db.Unscoped().Model(&models.UserRole{}).Count(&grants).Error)
		require.NoError(t, w.db.Model(&models.SystemMetadata{}).Where("key = ?", systemInitializedKey).Count(&marker).Error)
		assert.Equal(t, int64(1), users, "only the rival's row exists")
		assert.Zero(t, perms, "the rolled-back bootstrap seeded no permission")
		assert.Zero(t, roles, "the rolled-back bootstrap seeded no role")
		assert.Zero(t, grants, "no admin grant left behind")
		assert.Zero(t, marker, "the install is not marked initialised by a refused bootstrap")
	})
}
