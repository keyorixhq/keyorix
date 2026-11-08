//go:build !windows

package encryption_test

// process_crash_recovery_redproof_test.go shows that each oracle of
// FuzzProcessCrashRecovery fires on a state that breaks it. Nothing in production
// changes: I3 is broken by a driver wrapper that splits the DEK sweep's single
// transaction into two commits, the others by planting the damage after the kill.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	sqlitedialect "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
)

const pcrashSplitDriver = "sqlite-pcrash-split"

var pcrashSplitRegister sync.Once

// pcrashSplitConn commits the open transaction just before the second UPDATE of
// secret_versions and dies just after that statement, when splitting is on.
// With splitting off it dies at the same statement without the early commit,
// which is the control: the identical kill point on an intact transaction.
type pcrashSplitConn struct {
	driver.Conn
	split   bool
	updates *atomic.Int64
}

func (c *pcrashSplitConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	ex := c.Conn.(driver.ExecerContext)
	sweeps := strings.Contains(query, "secret_versions") && strings.HasPrefix(strings.TrimSpace(strings.ToUpper(query)), "UPDATE")
	if sweeps && c.updates.Add(1) == 2 {
		if c.split {
			for _, stmt := range []string{"COMMIT", "BEGIN IMMEDIATE"} {
				if _, err := ex.ExecContext(ctx, stmt, nil); err != nil {
					return nil, fmt.Errorf("split the transaction: %w", err)
				}
			}
		}
		if _, err := ex.ExecContext(ctx, query, args); err != nil {
			return nil, err
		}
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGKILL)
		select {}
	}
	return ex.ExecContext(ctx, query, args)
}

func (c *pcrashSplitConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

func (c *pcrashSplitConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}

type pcrashSplitDrv struct {
	inner   driver.Driver
	split   bool
	updates atomic.Int64
}

func (d *pcrashSplitDrv) Open(name string) (driver.Conn, error) {
	c, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return &pcrashSplitConn{Conn: c, split: d.split, updates: &d.updates}, nil
}

// runPCrashSplitAction is the "rotate-dek-split" and "rotate-dek-nosplit"
// actions: the real RotateDEKWithSweep, on a database handle through the wrapper.
func runPCrashSplitAction(action string) int {
	pass := os.Getenv(envPCrashPass)
	cfg, err := config.Load("keyorix.yaml")
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return pcrashExitHarness
	}
	probe, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		fmt.Fprintln(os.Stderr, "sqlite:", err)
		return pcrashExitHarness
	}
	inner := probe.Driver()
	_ = probe.Close()
	pcrashSplitRegister.Do(func() {
		sql.Register(pcrashSplitDriver, &pcrashSplitDrv{inner: inner, split: action == "rotate-dek-split"})
	})
	dsn := "file:" + cfg.Storage.Database.Path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_txlock=immediate&_pragma=synchronous(FULL)"
	db, err := gorm.Open(sqlitedialect.New(sqlitedialect.Config{DriverName: pcrashSplitDriver, DSN: dsn}), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		return pcrashExitHarness
	}
	svc := encryption.NewService(&cfg.Storage.Encryption, ".")
	if err := svc.Initialize(pass); err != nil {
		fmt.Fprintln(os.Stderr, "initialize:", err)
		return pcrashExitHarness
	}
	if _, err := svc.RotateDEKWithSweep(pass, db); err != nil {
		fmt.Fprintln(os.Stderr, "rotate:", err)
		return 1
	}
	return 0
}

// pcrashRedProof runs one input up to the state check, with damage planted
// between the operation and the check, and returns the violations.
func pcrashRedProof(t *testing.T, w *pcrashWorld, op pcrashOp, action string, killAt int64, plant func(dir string)) []string {
	t.Helper()
	dir := t.TempDir()
	if err := pcrashCopyTree(w.dir, dir); err != nil {
		t.Fatalf("copy template: %v", err)
	}
	st, err := w.prepare(dir, 1)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	cal := w.calibrate(t, op)
	after := &pcrashModel{Ledger: op.after(st.before.Ledger, w.seed.Ledger), Roles: cal.ref.Roles, Authz: cal.ref.Authz}
	var run pcrashChildRun
	if action != "" {
		run, err = runPCrashChild(dir, pcrashPass, action, nil, 0)
	} else {
		run, err = op.run(dir, pcrashPass, killAt)
	}
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if killAt > 0 || action != "" {
		if !run.killed {
			t.Fatalf("the child was not killed (exit %d): %s", run.exit, pcrashTail(run.output))
		}
	}
	if plant != nil {
		plant(dir)
	}
	return w.checkAfterDeath(t, op, dir, st, after)
}

func pcrashExecSQL(t *testing.T, dir, stmt string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "keyorix.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(stmt); err != nil {
		t.Fatalf("plant %q: %v", stmt, err)
	}
}

func pcrashWant(t *testing.T, v []string, name string) {
	t.Helper()
	for _, s := range v {
		if strings.HasPrefix(s, name+" ") {
			t.Logf("fired as expected: %s", pcrashTail(s))
			return
		}
	}
	t.Fatalf("oracle %s did not fire; violations: %v", name, v)
}

// TestProcessCrashRedProof needs child processes but is quick, so it runs by default.
func TestProcessCrashRedProof(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real child processes")
	}
	w := pcrashWorldFor(t)
	dek := pcrashOps[0]
	update := pcrashOps[5]

	t.Run("control-unbroken-kill-is-clean", func(t *testing.T) {
		if v := pcrashRedProof(t, w, dek, "rotate-dek-nosplit", 0, nil); len(v) > 0 {
			t.Fatalf("the unsplit sweep killed at the same statement must be clean: %v", v)
		}
	})
	t.Run("I3-split-transaction", func(t *testing.T) {
		pcrashWant(t, pcrashRedProof(t, w, dek, "rotate-dek-split", 0, nil), "I3")
	})
	t.Run("I1-database-destroyed", func(t *testing.T) {
		v := pcrashRedProof(t, w, update, "", 1, func(dir string) {
			for _, f := range []string{"keyorix.db-wal", "keyorix.db-shm"} {
				_ = os.Remove(filepath.Join(dir, f))
			}
			if err := os.WriteFile(filepath.Join(dir, "keyorix.db"), []byte("this is not a sqlite database at all"), 0o600); err != nil {
				t.Fatal(err)
			}
		})
		pcrashWant(t, v, "I1")
	})
	t.Run("I2-version-row-lost", func(t *testing.T) {
		v := pcrashRedProof(t, w, update, "", 1, func(dir string) {
			pcrashExecSQL(t, dir, "DELETE FROM secret_versions WHERE id = (SELECT MAX(v.id) FROM secret_versions v JOIN secret_nodes n ON n.id = v.secret_node_id WHERE n.name = 'pcrash-base-2')")
		})
		pcrashWant(t, v, "I2")
	})
	t.Run("I3-half-created-role", func(t *testing.T) {
		v := pcrashRedProof(t, w, update, "", 1, func(dir string) {
			pcrashExecSQL(t, dir, "INSERT INTO roles (name, name_folded, description) VALUES ('pcrash-planted', 'pcrash-planted', 'planted')")
		})
		pcrashWant(t, v, "I3")
	})
	t.Run("I3-undecryptable-version", func(t *testing.T) {
		v := pcrashRedProof(t, w, update, "", 1, func(dir string) {
			pcrashExecSQL(t, dir, "UPDATE secret_versions SET encrypted_value = randomblob(64) WHERE id = (SELECT MAX(id) FROM secret_versions)")
		})
		pcrashWant(t, v, "I3")
	})
	t.Run("I3-two-passphrases-open", func(t *testing.T) {
		// A real install cannot be opened by two passphrases on demand, so this
		// proves only the counting branch: the same passphrase offered twice.
		twice := update
		twice.kek = true
		twice.passes = []string{pcrashPass, pcrashPass}
		pcrashWant(t, pcrashRedProof(t, w, twice, "", 1, nil), "I3")
	})
	t.Run("I4-privilege-widened", func(t *testing.T) {
		v := pcrashRedProof(t, w, update, "", 1, func(dir string) {
			pcrashExecSQL(t, dir, "INSERT INTO user_roles (user_id, role_id, project_id, environment_id) SELECT u.id, r.id, 0, 0 FROM users u, roles r WHERE u.username = 'pcrash-bob' AND r.name = 'admin'")
		})
		pcrashWant(t, v, "I4")
	})
	t.Run("backup-after-kill-control-and-damage", func(t *testing.T) {
		const killAt = 12 // mid-rotation; any kill point that leaves the backup succeeding works
		if v := w.checkBackupAfterKilledRotation(t, killAt, 1, nil); len(v) > 0 {
			t.Fatalf("control: an undamaged restore must be clean: %v", v)
		}
		v := w.checkBackupAfterKilledRotation(t, killAt, 1, func(target string) {
			pcrashExecSQL(t, target, "UPDATE secret_versions SET encrypted_value = randomblob(64) WHERE id = (SELECT MAX(id) FROM secret_versions)")
		})
		if len(v) == 0 || !strings.Contains(v[0], "backup made after a kill") {
			t.Fatalf("the backup-after-kill oracle did not fire: %v", v)
		}
		t.Logf("fired as expected: %s", pcrashTail(v[0]))
	})
	for _, c := range []struct{ name, action, want string }{
		{"I5-rerun-panics", "rerun-panic", "I5"},
		{"I5-rerun-corrupts", "rerun-corrupt", "I5"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := pcrashCopyTree(w.dir, dir); err != nil {
				t.Fatal(err)
			}
			st, err := w.prepare(dir, 1)
			if err != nil {
				t.Fatal(err)
			}
			broken := pcrashOp{name: c.action, after: pcrashSame}
			cal := w.calibrate(t, pcrashOps[6])
			after := &pcrashModel{Ledger: st.before.Ledger.clone(), Roles: cal.ref.Roles, Authz: st.before.Authz}
			m := &pcrashModel{Ledger: st.before.Ledger, Roles: st.before.Roles, Authz: st.before.Authz}
			pcrashWant(t, w.checkRerun(t, broken, dir, pcrashPass, st, after, m), c.want)
		})
	}
}
