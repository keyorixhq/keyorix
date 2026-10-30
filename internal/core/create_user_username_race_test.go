package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	appstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// productionSchemaBackends runs fn on the production migration path (the storage
// factory) for SQLite and, when KEYORIX_TEST_PG_DSN is set, Postgres in an isolated
// schema. txClosureBackends' Postgres world is AutoMigrate only, which has none of
// the partial unique indexes (users username/email) these tests are about.
func productionSchemaBackends(t *testing.T, fn func(t *testing.T, w *txClosureWorld)) {
	t.Run("sqlite", func(t *testing.T) { fn(t, newGatedSQLiteWorld(t)) })
	t.Run("postgres", func(t *testing.T) {
		require.NoError(t, i18n.InitializeForTesting())
		cfg := &config.Config{Storage: config.StorageConfig{
			Type:     "postgres",
			Database: config.DatabaseConfig{DSN: pgIsolatedSchemaDSN(t, pgTestDSN(t))},
		}}
		st, err := appstorage.NewStorageFactory().CreateStorage(cfg)
		require.NoError(t, err)
		db, err := appstorage.OpenGormDB(cfg)
		require.NoError(t, err)
		t.Cleanup(func() {
			if sqlDB, e := db.DB(); e == nil {
				_ = sqlDB.Close()
			}
			if c, ok := st.(interface{ Close() error }); ok {
				_ = c.Close()
			}
		})
		fs := faultstorage.NewFaultyStorage(st, nil)
		fn(t, &txClosureWorld{c: NewKeyorixCore(fs), fs: fs, db: db})
	})
}

// AUTHZ-ORACLE-1 item 4 (REVFIX-3790-1 leftover): CreateUser's GetUserByUsername
// pre-check is a check-then-act read. Two concurrent creates of one username can
// both pass it; the loser's insert then fails on the partial unique index
// uniq_users_username_folded_active. That violation was not mapped to a sentinel,
// so the loser got "Storage failed: <constraint text>" (gRPC Internal, REST 500)
// where the winner's sequential check gives ErrUserAlreadyExists (AlreadyExists,
// 409). The race is reproduced deterministically: the winner's row is committed
// and the loser's pre-check is made to miss it. Production schema, SQLite and
// Postgres (productionSchemaBackends).
func TestCreateUser_UsernameRaceLoserGetsAlreadyExists(t *testing.T) {
	productionSchemaBackends(t, func(t *testing.T, w *txClosureWorld) {
		ctx := context.Background()
		require.NoError(t, w.db.Create(&models.User{
			Username: "Racer", UsernameFolded: "racer", Email: "winner@example.com", EmailFolded: "winner@example.com",
			IsActive: true, AccountState: AccountActive,
		}).Error)

		c := NewKeyorixCore(hooked(w.fs, &storeHooks{
			WrapTx: true,
			GetUserByUsername: func(_ storage.Storage, _ context.Context, _ string) (*models.User, error) {
				return nil, fmt.Errorf("lookup: %w", storage.ErrUserNotFound) // the winner has not committed yet
			},
		}))
		_, err := c.CreateUser(ctx, &CreateUserRequest{
			Username: "racer", Email: "loser@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrUserAlreadyExists, "the race loser must get the winner's answer: %v", err)
		assert.Contains(t, err.Error(), "username already exists")
		assert.NotContains(t, err.Error(), "username_folded", "the raw constraint text must not reach the caller")

		var n int64
		require.NoError(t, w.db.Model(&models.User{}).Where("username_folded = ?", "racer").Count(&n).Error)
		assert.Equal(t, int64(1), n)
	})
}
