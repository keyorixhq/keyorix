package main

// boot_exit_refusals_postgres_test.go -- EXIT78-1: a PostgreSQL whose
// session_replication_role is not "origin" is refused at boot, and only an
// operator can change that: exit 78, text unchanged. Gated on
// KEYORIX_TEST_PG_DSN (skips, not fails, when unset) like the other Postgres
// server tests.

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/testutil/pgpriv"
	"github.com/keyorixhq/keyorix/server/admin"
)

// replicaRoleInstall is a Postgres install whose DSN starts every session with
// session_replication_role=replica. It skips when KEYORIX_TEST_PG_DSN is unset
// or the role cannot start such a session.
func replicaRoleInstall(t *testing.T) *edgeInstall {
	t.Helper()
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
	return postgresInstall(t, dsn)
}

// TestBootExitCodes_AdminReplicationRoleRefusalIs78: `admin migrate` and the
// other admin commands open the same storage as the server, so the same refusal
// exits 78 there too (BOOT-REFUSAL-TRUTH-NOV-1), not 1.
func TestBootExitCodes_AdminReplicationRoleRefusalIs78(t *testing.T) {
	e := replicaRoleInstall(t)
	cmd := exec.Command(e.bin, "admin", "migrate", "--config", "./keyorix.yaml") //nolint:gosec // this suite's own binary
	cmd.Dir, cmd.Env = e.dir, e.env
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var ee *exec.ExitError
	require.ErrorAs(t, err, &ee, "admin migrate must fail:\n%s", out.String())
	if ee.ExitCode() != admin.ExitOperatorFix {
		t.Errorf("admin migrate exit status = %d, want %d (only removing the setting helps)\noutput:\n%s", ee.ExitCode(), admin.ExitOperatorFix, out.String())
	}
	const want = `refusing to start: PostgreSQL session_replication_role is "replica" for this server's database sessions, want "origin". `
	if !strings.Contains(out.String(), want) {
		t.Errorf("output lost the refusal text %q:\n%s", want, out.String())
	}
}

// TestAdminExitOperatorFixMatchesServer keeps the admin package's 78 equal to
// the server's: a systemd unit stops on one number for both.
func TestAdminExitOperatorFixMatchesServer(t *testing.T) {
	if admin.ExitOperatorFix != exitOperatorFix {
		t.Fatalf("admin.ExitOperatorFix = %d, server exitOperatorFix = %d", admin.ExitOperatorFix, exitOperatorFix)
	}
}

func TestBootExitCodes_ReplicationRoleRefusalIs78(t *testing.T) {
	e := replicaRoleInstall(t)
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
