package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AUTHZ-ORACLE-1 item 4: LocalStorage maps a collision on the users username index
// to storage.ErrDuplicateUsername and a collision on the email index to
// storage.ErrDuplicateEmail, never one for the other, on CreateUser and
// CreateUserWithRoleGrants, with the production schema on SQLite and Postgres.
func TestLocalStorage_UserUniqueViolationsAreTyped(t *testing.T) {
	productionSchemaBackends(t, func(t *testing.T, w *txClosureWorld) {
		ctx := context.Background()
		_, err := w.fs.CreateUser(ctx, &models.User{
			Username: "Taken", UsernameFolded: "taken", Email: "taken@example.com", EmailFolded: "taken@example.com",
		})
		require.NoError(t, err)

		sameName := func() *models.User {
			return &models.User{Username: "TAKEN", UsernameFolded: "taken", Email: "other@example.com", EmailFolded: "other@example.com"}
		}
		sameEmail := func() *models.User {
			return &models.User{Username: "other", UsernameFolded: "other", Email: "Taken@example.com", EmailFolded: "taken@example.com"}
		}

		_, err = w.fs.CreateUser(ctx, sameName())
		assert.ErrorIs(t, err, storage.ErrDuplicateUsername)
		assert.NotErrorIs(t, err, storage.ErrDuplicateEmail)
		_, err = w.fs.CreateUserWithRoleGrants(ctx, sameName(), nil)
		assert.ErrorIs(t, err, storage.ErrDuplicateUsername)
		assert.NotErrorIs(t, err, storage.ErrDuplicateEmail)

		_, err = w.fs.CreateUser(ctx, sameEmail())
		assert.ErrorIs(t, err, storage.ErrDuplicateEmail)
		assert.NotErrorIs(t, err, storage.ErrDuplicateUsername)
		_, err = w.fs.CreateUserWithRoleGrants(ctx, sameEmail(), nil)
		assert.ErrorIs(t, err, storage.ErrDuplicateEmail)
		assert.NotErrorIs(t, err, storage.ErrDuplicateUsername)
	})
}
