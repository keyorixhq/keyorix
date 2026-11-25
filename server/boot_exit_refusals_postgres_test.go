package main

// boot_exit_refusals_postgres_test.go -- EXIT78-1: a PostgreSQL whose
// session_replication_role is not "origin" is refused at boot, and only an
// operator can change that: exit 78, text unchanged. Gated on
// KEYORIX_TEST_PG_DSN (skips, not fails, when unset) like the other Postgres
// server tests.

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/testutil/pgpriv"
)

func TestBootExitCodes_ReplicationRoleRefusalIs78(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the server")
	}
	base := os.Getenv("KEYORIX_TEST_PG_DSN")
	if base == "" {
		t.Skip("KEYORIX_TEST_PG_DSN is not set")
	}
	// Starting a session in replica mode needs SUPERUSER (or GRANT SET ON
	// PARAMETER); skips without it, fails under CI=true.
	probe, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	pgpriv.RequireReplicationRolePrivilege(t, probe)
	dsn := adminPgIsolatedDatabaseDSN(t, base)
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn += sep + "options=-c%20session_replication_role%3Dreplica"
	} else {
		dsn += " options='-c session_replication_role=replica'"
	}
	e := postgresInstall(t, dsn)
	code, stderr := bootAttempt(t, e, bootEnv(e), "--passphrase-file=./pass")
	if code != 78 {
		t.Errorf("exit status = %d, want 78 (only removing the setting helps)\nstderr:\n%s", code, stderr)
	}
	const want = `failed to initialize storage: refusing to start: PostgreSQL session_replication_role is "replica" for this server's database sessions, want "origin". `
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr lost the refusal text %q:\n%s", want, stderr)
	}
	requireHint(t, e, stderr, "keyorix-server: exit 78 ")
}
