package store

// #3620 (SCIM-GROUPS-ERR-1): LocalStorage.GetGroup and DeleteGroup answer
// storage.ErrGroupNotFound for a missing (or soft-deleted) row and ONLY for that. The
// SCIM Group handlers turn the sentinel into a 404 that an IdP reads as "the group is
// gone"; a database failure carrying it would make an IdP drop or re-create a group
// that exists. Runs on SQLite always and on Postgres when KEYORIX_TEST_PG_DSN is set
// (the two drivers word a missing row and a missing table differently).

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// groupBackends yields a LocalStorage with only the groups table, per available backend.
func groupBackends(t *testing.T) map[string]func(*testing.T) *LocalStorage {
	t.Helper()
	return map[string]func(*testing.T) *LocalStorage{
		"sqlite": func(t *testing.T) *LocalStorage {
			return newPartialSecretsDB(t, &models.Group{})
		},
		"postgres": func(t *testing.T) *LocalStorage {
			dsn := requirePostgresDSN(t)
			db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
			require.NoError(t, err)
			schema := "grp_nf_" + strings.ToLower(strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
			if len(schema) > 60 {
				schema = schema[:60]
			}
			require.NoError(t, db.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
			require.NoError(t, db.Exec("CREATE SCHEMA "+schema).Error)
			t.Cleanup(func() { _ = db.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error })
			sqlDB, err := db.DB()
			require.NoError(t, err)
			// One connection, so SET search_path stays on the session every query uses.
			sqlDB.SetMaxOpenConns(1)
			require.NoError(t, db.Exec("SET search_path TO "+schema).Error)
			require.NoError(t, db.AutoMigrate(&models.Group{}))
			return NewLocalStorage(db)
		},
	}
}

func TestGroupLookups_NotFoundIsTyped_FailureIsNot(t *testing.T) {
	for backend, open := range groupBackends(t) {
		t.Run(backend, func(t *testing.T) {
			ctx := context.Background()

			t.Run("missing row", func(t *testing.T) {
				ls := open(t)
				_, err := ls.GetGroup(ctx, 4242)
				require.ErrorIs(t, err, storage.ErrGroupNotFound)
				require.ErrorIs(t, ls.DeleteGroup(ctx, 4242), storage.ErrGroupNotFound)
			})

			t.Run("soft-deleted row", func(t *testing.T) {
				ls := open(t)
				g, err := ls.CreateGroup(ctx, &models.Group{Name: "gone", NameFolded: "gone"})
				require.NoError(t, err)
				require.NoError(t, ls.DeleteGroup(ctx, g.ID))
				_, err = ls.GetGroup(ctx, g.ID)
				require.ErrorIs(t, err, storage.ErrGroupNotFound)
				require.ErrorIs(t, ls.DeleteGroup(ctx, g.ID), storage.ErrGroupNotFound)
			})

			t.Run("live row is found", func(t *testing.T) {
				ls := open(t)
				g, err := ls.CreateGroup(ctx, &models.Group{Name: "here", NameFolded: "here"})
				require.NoError(t, err)
				got, err := ls.GetGroup(ctx, g.ID)
				require.NoError(t, err)
				assert.Equal(t, "here", got.Name)
			})

			// The table is gone: a database failure, not an absent group. It must not
			// carry the sentinel, or the handler would answer 404 for an outage.
			t.Run("database failure is not not-found", func(t *testing.T) {
				ls := open(t)
				g, err := ls.CreateGroup(ctx, &models.Group{Name: "exists", NameFolded: "exists"})
				require.NoError(t, err)
				require.NoError(t, ls.db.Exec("DROP TABLE groups").Error)

				_, err = ls.GetGroup(ctx, g.ID)
				require.Error(t, err)
				assert.NotErrorIs(t, err, storage.ErrGroupNotFound)
				err = ls.DeleteGroup(ctx, g.ID)
				require.Error(t, err)
				assert.NotErrorIs(t, err, storage.ErrGroupNotFound)
			})
		})
	}
}
