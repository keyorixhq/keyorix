// factory_fresh_install_crash_postgres_test.go — the real-Postgres counterpart
// to factory_fresh_install_crash_test.go's SQLite crash-consistency proof.
// Postgres was never exposed to the underlying bug (withMigrationLock already
// wraps the ENTIRE migrateDatabase call in one db.Transaction for Postgres —
// see withMigrationLock's isPostgres branch), but this proves the FIX itself
// — wrapping the fresh-install tail in its own db.Transaction — is also
// correct and self-heals on Postgres when driven directly (bypassing
// withMigrationLock's outer transaction, so this test exercises the new inner
// transaction on its own, the same way the SQLite test does), not just that
// Postgres happened to be safe before. Gated on KEYORIX_TEST_PG_DSN so
// `go test ./...` still passes cleanly with no Postgres available.
package storage

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFreshInstall_InterruptedAutoMigrateLoop_Postgres_NextBootSelfHeals(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	base := pgTestDSN(t)
	dsn := pgIsolatedDatabaseDSN(t, base)

	db1 := pgRawOpen(t, dsn)
	f := &DefaultStorageFactory{}
	crashErr := runMigrateWithCrash(f, db1, "freshinstall:after:*models.Project")
	require.NoError(t, crashErr)

	// Simulate the next boot: a fresh connection to the SAME Postgres database.
	db2 := pgRawOpen(t, dsn)
	bootErr := f.migrateDatabase(db2)
	require.NoError(t, bootErr, "next boot's migrateDatabase must not itself fail")

	assert.True(t, tableExists(db2, "users"),
		"the fresh-install transaction must have rolled back the interrupted attempt "+
			"entirely (including the projects table), so the next boot's migrateDatabase "+
			"correctly saw projectsExists=false and retried the full sequence from scratch")
}
