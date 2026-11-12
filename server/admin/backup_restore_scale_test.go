// backup_restore_scale_test.go (RECOVERY-SCALE-1, #3462): `admin backup` and
// `admin restore` on a database far bigger than the unit-test fixtures, with
// real binaries, run only when KEYORIX_SCALE_TESTS=1 so the default suite
// stays fast.
//
// The rig is scripts/migrate/scale-check.sh (SCALE-OPS-1). It fills a SQLite
// instance with scripts/migrate/scalegen (secrets with versions, shares, users,
// access-log rows and a chained audit log), then runs each of
//
//	verify-audit, backup, restore into an empty SQLite, verify-audit on it,
//
// as its own process under scripts/migrate/rssrun (peak RSS from wait4), and
// compares every table (row count and checksum) between source and target. It
// does this at two sizes and FAILS if the peak RSS of any leg at the larger
// size is out of proportion to the smaller one: a table loaded whole into memory
// grows with the row count; a bounded streaming path does not. Peak RSS is used
// rather than runtime.MemStats because the work happens in the server binary,
// not in this test process.
//
// With KEYORIX_SCALE_PG_DSN_FILE naming a file that holds the URL of an EMPTY
// PostgreSQL database (kpg dsn <name>), the same run also moves the data
// SQLite -> PostgreSQL and PostgreSQL -> SQLite and compares every table of each
// target with the source, which covers users, roles, shares and keys as well as
// secrets and the audit log, and verifies the audit chain on every target.
//
// KEYORIX_SCALE_AUDIT (default 100000) and KEYORIX_SCALE_SECRETS (default 20000)
// size the smaller run; the larger one is 5x, i.e. 500000 audit rows and 100000
// secrets with 3 versions each at the defaults.
package admin

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func scaleRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "scripts", "migrate", "scale-check.sh")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "repository root with scripts/migrate/scale-check.sh not found")
		dir = parent
	}
}

func scaleEnvOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func TestScale_BackupRestoreMemoryBoundedAndRoundTrip(t *testing.T) {
	if os.Getenv("KEYORIX_SCALE_TESTS") != "1" {
		t.Skip("scale test: set KEYORIX_SCALE_TESTS=1 (builds the server and fills ~500k audit rows; minutes, not seconds)")
	}
	root := scaleRepoRoot(t)
	out := t.TempDir()

	cmd := exec.Command("bash", filepath.Join(root, "scripts", "migrate", "scale-check.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"SCALE_FACTORS=1 5",
		"SCALE_BASE_AUDIT="+scaleEnvOr("KEYORIX_SCALE_AUDIT", "100000"),
		"SCALE_BASE_SECRETS="+scaleEnvOr("KEYORIX_SCALE_SECRETS", "20000"),
		"SCALE_MODE=measure",
		"SCALE_OUT="+out,
	)
	if f := os.Getenv("KEYORIX_SCALE_PG_DSN_FILE"); f != "" {
		cmd.Env = append(cmd.Env, "MIGRATE_PG_DSN_FILE="+f)
	} else {
		t.Log("KEYORIX_SCALE_PG_DSN_FILE not set: SQLite legs only; the PostgreSQL directions are not exercised")
	}

	start := time.Now()
	combined, err := cmd.CombinedOutput()
	log := string(combined)
	if err != nil {
		// The harness prints its own "DRILL FAILED: <reason>"; show only the tail of a long run.
		lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
		if len(lines) > 40 {
			lines = lines[len(lines)-40:]
		}
		t.Fatalf("scale-check.sh failed after %s: %v\n%s", time.Since(start).Round(time.Second), err, strings.Join(lines, "\n"))
	}
	// A run that "passed" without the checks having run is not a pass.
	require.Contains(t, log, "every table equal to the source", "the table comparison did not run")
	require.Contains(t, log, "limit ", "the memory assertion did not run")
	t.Logf("scale-check.sh passed in %s", time.Since(start).Round(time.Second))
}
