// factory_mfa_enrolment_not_null_test.go — #4517: users.mfa_enrolment_required is NOT NULL on
// a fresh install (the model's `not null` tag) as well as on an upgrade (migrate_users.go).
//
// A database first installed by an earlier pre-release build holds the column nullable, and
// may hold NULL rows. Nothing in migrateDatabase tightens it (GORM's AutoMigrate only ever
// relaxes a NOT NULL column, never adds the constraint), so the NOT NULL tag cannot fail a
// boot on such a database: no backfill is needed because no step changes the column.
package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestMFAEnrolmentRequired_FreshInstallIsNotNull(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "fresh.db"))
	require.NoError(t, err)
	require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))

	cols, err := db.Migrator().ColumnTypes(&models.User{})
	require.NoError(t, err)
	for _, c := range cols {
		if c.Name() == "mfa_enrolment_required" {
			nullable, ok := c.Nullable()
			require.True(t, ok)
			require.False(t, nullable, "a fresh install must declare users.mfa_enrolment_required NOT NULL, like the upgrade's ALTER")
			return
		}
	}
	t.Fatal("users.mfa_enrolment_required is missing from a fresh install")
}

func TestMFAEnrolmentRequired_ExistingNullableColumnWithNullRowsStillBoots(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "nullable.db"))
	require.NoError(t, err)
	assertNullableColumnBoots(t, db)
}

func TestMFAEnrolmentRequired_Postgres_ExistingNullableColumnWithNullRowsStillBoots(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	assertNullableColumnBoots(t, pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t))))
}

// assertNullableColumnBoots leaves db the way a pre-release fresh install did (the column
// nullable, one row holding NULL), makes the next boot take the fresh-install tail (whose
// AutoMigrate of models.User is the step the NOT NULL tag could have broken), and boots it.
func assertNullableColumnBoots(t *testing.T, db *gorm.DB) {
	t.Helper()
	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	require.NoError(t, db.Create(&models.User{Username: "nullable-mfa", Email: "nullable-mfa@example.test"}).Error)
	require.NoError(t, db.Exec("ALTER TABLE users DROP COLUMN mfa_enrolment_required").Error)
	require.NoError(t, db.Exec("ALTER TABLE users ADD COLUMN mfa_enrolment_required BOOLEAN DEFAULT false").Error)
	require.NoError(t, db.Exec("UPDATE users SET mfa_enrolment_required = NULL").Error)
	require.NoError(t, db.Exec("DROP TABLE mfa_step_up_grants").Error)

	require.NoError(t, f.migrateDatabase(db), "boot against a nullable users.mfa_enrolment_required holding NULL rows")
	require.True(t, tableExists(db, "mfa_step_up_grants"), "setup: the fresh-install tail must have run")
}
