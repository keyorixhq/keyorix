package store

// RestoreProject on Postgres under a non-ISO DateStyle (REVIEW-3921-DEEP-1 F2). CAST(timestamptz
// AS TEXT) renders in the session's DateStyle, so a candidate scan that parsed that text skipped
// every cascade child under 'SQL, DMY', 'German' or 'Postgres, MDY': the project came back with its
// environments and secrets still deleted, and the secrets kept their frozen purge_at. pg-gated
// (KEYORIX_TEST_PG_DSN).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// newRestorePGStore is newRestoreTestStore on Postgres, in a schema of its own, on ONE connection
// so a session SET (DateStyle) holds for every statement RestoreProject runs.
func newRestorePGStore(t *testing.T) *LocalStorage {
	t.Helper()
	dsn := requirePostgresDSN(t)
	var suffix [6]byte
	_, err := rand.Read(suffix[:])
	require.NoError(t, err)
	schema := "restore_datestyle_" + hex.EncodeToString(suffix[:])
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: gormlogger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if a, e := admin.DB(); e == nil {
			_ = a.Close()
		}
	})
	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), &gorm.Config{Logger: gormlogger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.ShareRecord{},
		&models.SecretACL{}, &models.AccessRequest{}, &models.DynamicSecretConfig{}))
	return NewLocalStorage(db)
}

func TestRestoreProject_PostgresIndependentOfDateStyle(t *testing.T) {
	for _, style := range []string{"ISO, MDY", "SQL, DMY", "German", "Postgres, MDY"} {
		t.Run(style, func(t *testing.T) {
			ctx := context.Background()
			ls := newRestorePGStore(t)

			proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
			require.NoError(t, err)
			env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
			require.NoError(t, err)
			earlier, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "old", ProjectID: proj.ID})
			require.NoError(t, err)
			secret, err := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: proj.ID, EnvironmentID: env.ID, Name: "s",
				IsSecret: true, Type: "text", Status: "active"})
			require.NoError(t, err)

			// One cascade stamp on the project and its children; one environment retired a minute
			// before it, which must stay deleted.
			cascade := time.Date(2026, 11, 1, 11, 56, 1, 123456000, time.UTC)
			frozenPurge := cascade.AddDate(0, 1, 0)
			require.NoError(t, ls.db.Exec("UPDATE projects SET deleted_at = ? WHERE id = ?", cascade, proj.ID).Error)
			require.NoError(t, ls.db.Exec("UPDATE environments SET deleted_at = ? WHERE id = ?", cascade, env.ID).Error)
			require.NoError(t, ls.db.Exec("UPDATE environments SET deleted_at = ? WHERE id = ?", cascade.Add(-time.Minute), earlier.ID).Error)
			require.NoError(t, ls.db.Exec("UPDATE secret_nodes SET deleted_at = ?, purge_at = ? WHERE id = ?", cascade, frozenPurge, secret.ID).Error)

			require.NoError(t, ls.db.Exec("SET datestyle = '"+style+"'").Error)
			// The premise: under a non-ISO style the text form is not the ISO one.
			var rendered string
			require.NoError(t, ls.db.Raw("SELECT CAST(deleted_at AS TEXT) FROM environments WHERE id = ?", env.ID).Scan(&rendered).Error)
			if !strings.HasPrefix(style, "ISO") {
				require.NotContains(t, rendered, "2026-11-01", "DateStyle %q did not take effect: %q", style, rendered)
			}

			restoredEnvs, restoredSecrets, err := ls.RestoreProject(ctx, proj.ID)
			require.NoError(t, err)
			require.Equal(t, 1, restoredEnvs, "the cascade environment is restored")
			require.Equal(t, 1, restoredSecrets, "the cascade secret is restored")

			var envDeleted, earlierDeleted, secretDeleted, secretPurge bool
			require.NoError(t, ls.db.Raw("SELECT deleted_at IS NOT NULL FROM environments WHERE id = ?", env.ID).Scan(&envDeleted).Error)
			require.NoError(t, ls.db.Raw("SELECT deleted_at IS NOT NULL FROM environments WHERE id = ?", earlier.ID).Scan(&earlierDeleted).Error)
			require.NoError(t, ls.db.Raw("SELECT deleted_at IS NOT NULL FROM secret_nodes WHERE id = ?", secret.ID).Scan(&secretDeleted).Error)
			require.NoError(t, ls.db.Raw("SELECT purge_at IS NOT NULL FROM secret_nodes WHERE id = ?", secret.ID).Scan(&secretPurge).Error)
			require.False(t, envDeleted)
			require.True(t, earlierDeleted, "an environment retired before the cascade stays deleted")
			require.False(t, secretDeleted)
			require.False(t, secretPurge, "a restored secret loses its frozen purge date")
		})
	}
}
