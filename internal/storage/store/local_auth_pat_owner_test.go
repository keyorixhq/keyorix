// local_auth_pat_owner_test.go — GetPersonalAccessTokenWithOwnerByHash, the
// one-statement token + owner read behind core.CurrentPATRestriction.
package store

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestGetPersonalAccessTokenWithOwnerByHash(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) *LocalStorage {
		t.Helper()
		ls := newS22Store(t, &models.User{}, &models.PersonalAccessToken{})
		require.NoError(t, ls.db.Create(&models.User{ID: 7, Username: "owner", Email: "owner@example.com", IsActive: true, AccountState: "active"}).Error)
		require.NoError(t, ls.db.Create(&models.PersonalAccessToken{ID: 1, UserID: 7, Name: "ci", TokenHash: "hash-7", Scopes: `["secrets.read"]`}).Error)
		return ls
	}

	t.Run("active owner", func(t *testing.T) {
		ls := setup(t)
		pat, owner, err := ls.GetPersonalAccessTokenWithOwnerByHash(ctx, "hash-7")
		require.NoError(t, err)
		require.Equal(t, uint(1), pat.ID)
		require.Equal(t, uint(7), pat.UserID)
		require.Equal(t, `["secrets.read"]`, pat.Scopes, "the token's own columns come back intact")
		require.True(t, owner.Found)
		require.True(t, owner.IsActive)
		require.Equal(t, "active", owner.AccountState)
	})

	t.Run("suspended owner reads its state", func(t *testing.T) {
		ls := setup(t)
		require.NoError(t, ls.db.Model(&models.User{}).Where("id = ?", 7).Update("account_state", "suspended").Error)
		_, owner, err := ls.GetPersonalAccessTokenWithOwnerByHash(ctx, "hash-7")
		require.NoError(t, err)
		require.True(t, owner.Found)
		require.Equal(t, "suspended", owner.AccountState)
	})

	t.Run("deactivated owner reads inactive", func(t *testing.T) {
		ls := setup(t)
		require.NoError(t, ls.db.Model(&models.User{}).Where("id = ?", 7).Update("is_active", false).Error)
		_, owner, err := ls.GetPersonalAccessTokenWithOwnerByHash(ctx, "hash-7")
		require.NoError(t, err)
		require.True(t, owner.Found)
		require.False(t, owner.IsActive)
	})

	t.Run("soft-deleted owner is not found", func(t *testing.T) {
		ls := setup(t)
		require.NoError(t, ls.db.Delete(&models.User{}, 7).Error)
		pat, owner, err := ls.GetPersonalAccessTokenWithOwnerByHash(ctx, "hash-7")
		require.NoError(t, err, "a missing owner is not an error; the token row still reads")
		require.Equal(t, uint(1), pat.ID)
		require.False(t, owner.Found, "a soft-deleted owner must not read as its stale (active) state")
	})

	t.Run("hard-deleted owner is not found", func(t *testing.T) {
		ls := setup(t)
		require.NoError(t, ls.db.Unscoped().Delete(&models.User{}, 7).Error)
		_, owner, err := ls.GetPersonalAccessTokenWithOwnerByHash(ctx, "hash-7")
		require.NoError(t, err)
		require.False(t, owner.Found)
	})

	t.Run("missing token is a record-not-found error", func(t *testing.T) {
		ls := setup(t)
		pat, _, err := ls.GetPersonalAccessTokenWithOwnerByHash(ctx, "no-such-hash")
		require.Nil(t, pat)
		require.True(t, errors.Is(err, gorm.ErrRecordNotFound),
			"same error shape as GetPersonalAccessTokenByHash, so core's credentialRowGone still sees a deleted token: %v", err)
	})
}
