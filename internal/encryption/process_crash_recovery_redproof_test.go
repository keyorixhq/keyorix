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

// pcrashBackupAtKill kills a DEK rotation at killAt and takes a backup with no
// restart in between; the archive is post.tar.gz in the returned install.
func pcrashBackupAtKill(t *testing.T, w *pcrashWorld, killAt int64) (string, pcrashExecState, string) {
	t.Helper()
	dir := t.TempDir()
	if err := pcrashCopyTree(w.dir, dir); err != nil {
		t.Fatalf("copy template: %v", err)
	}
	st, err := w.prepare(dir, 0)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	run, err := pcrashOps[0].run(dir, pcrashPass, killAt)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !run.killed {
		t.Fatalf("the rotation was not killed (exit %d): %s", run.exit, pcrashTail(run.output))
	}
	b, err := runPCrashChild(dir, pcrashPass, "admin", []string{"backup", "--config", "./keyorix.yaml", "--output", "./post.tar.gz"}, 0)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if b.exit != 0 {
		t.Fatalf("backup after the kill exited %d: %s", b.exit, pcrashTail(b.output))
	}
	return dir, st, run.label
}

// pcrashCleanHostOutcome runs the clean-host check in a subtest of its own, so a
// skip is reported to the caller instead of ending the caller's test.
func pcrashCleanHostOutcome(t *testing.T, w *pcrashWorld, dir, label string, st pcrashExecState) (v []string, skipped bool) {
	t.Helper()
	t.Run("check", func(t *testing.T) {
		defer func() { skipped = t.Skipped() }()
		v = w.checkCleanHostRestore(t, dir, label, st)
	})
	return v, skipped
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
// Each subtest works on its own copy of the template (the calibration cache is
// locked), so they run in parallel, as TestProcessCrashExhaustive's do.
// TestProcessCrashRedProof runs in the nightly, not in plain `go test`: see
// pcrashSkipUnlessRequested.
func TestProcessCrashRedProof(t *testing.T) {
	pcrashSkipUnlessRequested(t, "show each crash oracle firing")
	w := pcrashWorldFor(t)
	dek := pcrashOps[0]
	update := pcrashOps[5]

	// One serial group around the parallel subtests, so this test's reported time
	// includes them (scripts/ci/gen-test-weights.py reads the top-level line).
	t.Run("oracles", func(t *testing.T) {
		t.Run("control-unbroken-kill-is-clean", func(t *testing.T) {
			t.Parallel()
			if v := pcrashRedProof(t, w, dek, "rotate-dek-nosplit", 0, nil); len(v) > 0 {
				t.Fatalf("the unsplit sweep killed at the same statement must be clean: %v", v)
			}
		})
		t.Run("I3-split-transaction", func(t *testing.T) {
			t.Parallel()
			pcrashWant(t, pcrashRedProof(t, w, dek, "rotate-dek-split", 0, nil), "I3")
		pcrashWant(t, v, "I1")
	})
	t.Run("I1-refusal-must-be-the-products", func(t *testing.T) {
		// A directory in the DEK's place fails in key reconciliation or key
		// initialization, and is no refusal an operator is told how to resolve.
		v := pcrashRedProof(t, w, update, "", 1, func(dir string) {
			dek := filepath.Join(dir, "keys", "dek.key")
			if err := os.Remove(dek); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dek, 0o700); err != nil {
				t.Fatal(err)
			}
		})
		pcrashWant(t, v, "I1 reopen failed without a documented")
	})
	t.Run("control-product-refusals-are-documented", func(t *testing.T) {
		wrongFirst := update
		wrongFirst.passes = []string{"pcrash-not-the-passphrase", pcrashPass}
		if v := pcrashRedProof(t, w, wrongFirst, "", 1, nil); len(v) > 0 {
			t.Fatalf("a wrong passphrase is a documented refusal: %v", v)
		}
		v := pcrashRedProof(t, w, update, "", 1, func(dir string) {
			if err := os.Remove(filepath.Join(dir, "keys", "dek.key")); err != nil {
				t.Fatal(err)
			}
		})
		pcrashWant(t, v, "I1 no passphrase opens")
		dir := t.TempDir()
		if err := pcrashCopyTree(w.dir, dir); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".keyorix-restore-journal.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		o := pcrashOpenGuarded(dir, pcrashPass)
		if o.err == nil || !pcrashExplicitOpenError(o.err) {
			t.Fatalf("the restore journal refusal is documented: inst=%v err=%v", o.inst != nil, o.err)
		}
	})
	t.Run("I2-version-row-lost", func(t *testing.T) {
		v := pcrashRedProof(t, w, update, "", 1, func(dir string) {
			pcrashExecSQL(t, dir, "DELETE FROM secret_versions WHERE id = (SELECT MAX(v.id) FROM secret_versions v JOIN secret_nodes n ON n.id = v.secret_node_id WHERE n.name = 'pcrash-base-2')")
		})
		t.Run("I1-database-destroyed", func(t *testing.T) {
			t.Parallel()
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
			t.Parallel()
			v := pcrashRedProof(t, w, update, "", 1, func(dir string) {
				pcrashExecSQL(t, dir, "DELETE FROM secret_versions WHERE id = (SELECT MAX(v.id) FROM secret_versions v JOIN secret_nodes n ON n.id = v.secret_node_id WHERE n.name = 'pcrash-base-2')")
			})
			pcrashWant(t, v, "I2")
		})
		t.Run("I3-half-created-role", func(t *testing.T) {
			t.Parallel()
			v := pcrashRedProof(t, w, update, "", 1, func(dir string) {
				pcrashExecSQL(t, dir, "INSERT INTO roles (name, name_folded, description) VALUES ('pcrash-planted', 'pcrash-planted', 'planted')")
			})
			pcrashWant(t, v, "I3")
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
	t.Run("I3-mixed-roles-after-authorization-before", func(t *testing.T) {
		mixed := pcrashOp{name: "role-mixed", after: pcrashSame}
		if v := pcrashRedProof(t, w, mixed, "role-mixed-die-first", 0, nil); len(v) > 0 {
			t.Fatalf("control: killed before either write is wholly before: %v", v)
		}
		if v := pcrashRedProof(t, w, mixed, "", 0, nil); len(v) > 0 {
			t.Fatalf("control: a completed run is wholly after: %v", v)
		}
		pcrashWant(t, pcrashRedProof(t, w, mixed, "role-mixed-die-between", 0, nil), "I3 state mixes before and")
	})
	t.Run("I4-privilege-widened", func(t *testing.T) {
		v := pcrashRedProof(t, w, update, "", 1, func(dir string) {
			pcrashExecSQL(t, dir, pcrashWidenBobSQL)
		})
		t.Run("I3-undecryptable-version", func(t *testing.T) {
			t.Parallel()
			v := pcrashRedProof(t, w, update, "", 1, func(dir string) {
				pcrashExecSQL(t, dir, "UPDATE secret_versions SET encrypted_value = randomblob(64) WHERE id = (SELECT MAX(id) FROM secret_versions)")
			})
			pcrashWant(t, v, "I3")
		})
		t.Run("I3-two-passphrases-open", func(t *testing.T) {
			t.Parallel()
			// A real install cannot be opened by two passphrases on demand, so this
			// proves only the counting branch: the same passphrase offered twice.
			// The calibration cache is keyed by name, and a kek op reopens with the new
			// passphrase: calibrate the plain update first, as the serial order did.
			w.calibrate(t, update)
			twice := update
			twice.kek = true
			twice.passes = []string{pcrashPass, pcrashPass}
			pcrashWant(t, pcrashRedProof(t, w, twice, "", 1, nil), "I3")
		pcrashWant(t, v, "I5")
	})
	t.Run("backup-after-kill-control-and-damage", func(t *testing.T) {
		// After the DEK rename, so dek.key.pending is gone: the control also goes
		// through the clean-host restore, which #4058 skips while the file exists.
		killAt := w.seamNamed(t, dek, "sweep:after-rename-dek")
		if v := w.checkBackupAfterKilledRotation(t, killAt, 0, nil); len(v) > 0 {
			t.Fatalf("control: an undamaged restore must be clean: %v", v)
		}
		v := w.checkBackupAfterKilledRotation(t, killAt, 0, func(target string) {
			pcrashExecSQL(t, target, "UPDATE secret_versions SET encrypted_value = randomblob(64) WHERE id = (SELECT MAX(id) FROM secret_versions)")
		})
		t.Run("I4-privilege-widened", func(t *testing.T) {
			t.Parallel()
			v := pcrashRedProof(t, w, update, "", 1, func(dir string) {
				pcrashExecSQL(t, dir, "INSERT INTO user_roles (user_id, role_id, project_id, environment_id) SELECT u.id, r.id, 0, 0 FROM users u, roles r WHERE u.username = 'pcrash-bob' AND r.name = 'admin'")
			})
			pcrashWant(t, v, "I4")
		})
		t.Run("I5-migration-schema-differs", func(t *testing.T) {
			t.Parallel()
			if v := w.runPCrashMigrate(t, 1, nil); len(v) > 0 {
				t.Fatalf("control: an undamaged migration must be clean: %v", v)
			}
			v := w.runPCrashMigrate(t, 1, func(dir string) {
				pcrashExecSQL(t, dir, "DROP TABLE secret_tags")
			})
			pcrashWant(t, v, "I5")
		if len(v) == 0 || !strings.Contains(v[0], "backup made after a kill") {
			t.Fatalf("the backup-after-kill oracle did not fire: %v", v)
		}
		t.Logf("fired as expected: %s", pcrashTail(v[0]))
	})
	t.Run("clean-host-restore", func(t *testing.T) {
		// A pending DEK is on disk from here until the rename, and in the backup.
		killAt := w.seamNamed(t, dek, "sweep:after-sweep-commit")
		t.Run("control-completed-rotation-restores", func(t *testing.T) {
			if v := w.checkBackupAfterCompletedRotation(t); len(v) > 0 {
				t.Fatalf("a backup after a completed rotation must restore on a clean host: %v", v)
			}
		})
		t.Run("4058-skips-while-pending-exists", func(t *testing.T) {
			dir, st, label := pcrashBackupAtKill(t, w, killAt)
			v, skipped := pcrashCleanHostOutcome(t, w, dir, label, st)
			if !skipped {
				t.Fatalf("#4058 no longer skips (fixed? then remove the skip in checkCleanHostRestore): %v", v)
			}
		})
		t.Run("refusal-without-pending-stays-red", func(t *testing.T) {
			dir, st, label := pcrashBackupAtKill(t, w, killAt)
			if err := os.Remove(filepath.Join(dir, "keys", "dek.key.pending")); err != nil {
				t.Fatal(err)
			}
			v, skipped := pcrashCleanHostOutcome(t, w, dir, label, st)
			if skipped || len(v) == 0 || !strings.Contains(v[0], "refused on a clean host") {
				t.Fatalf("the refusal must fail once dek.key.pending is gone: skipped=%v v=%v", skipped, v)
			}
			t.Logf("fired as expected: %s", pcrashTail(v[0]))
		})
		t.Run("other-refusal-with-pending-stays-red", func(t *testing.T) {
			dir, st, label := pcrashBackupAtKill(t, w, killAt)
			archive := filepath.Join(dir, "post.tar.gz")
			info, err := os.Stat(archive)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(archive, info.Size()/2); err != nil {
				t.Fatal(err)
			}
			v, skipped := pcrashCleanHostOutcome(t, w, dir, label, st)
			if skipped || len(v) == 0 || !strings.Contains(v[0], "refused on a clean host") {
				t.Fatalf("a different refusal must fail even with dek.key.pending present: skipped=%v v=%v", skipped, v)
			}
			t.Logf("fired as expected: %s", pcrashTail(v[0]))
		})
	})
	for _, c := range []struct{ name, action, want string }{
		{"I5-rerun-panics", "rerun-panic", "I5"},
		{"I5-rerun-corrupts", "rerun-corrupt", "I5"},
		{"I5-completed-rerun-moves-authorization", "rerun-widen", "I5 authorization after a completed"},
		{"I5-refused-rerun-moves-authorization", "rerun-refuse-widen", "I5 authorization after a refused"},
		{"control-rerun-completes-unchanged", "rerun-noop", ""},
		{"control-rerun-refuses-unchanged", "rerun-refuse", ""},
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
			v := w.checkRerun(t, broken, dir, pcrashPass, st, after, m)
			if c.want == "" {
				if len(v) > 0 {
					t.Fatalf("control: %v", v)
				}
				return
			}
			pcrashWant(t, v, c.want)
		})
		t.Run("backup-after-kill-control-and-damage", func(t *testing.T) {
			t.Parallel()
			// Since BACKUP-PENDING-ROTATION-1 a backup is refused at every kill point
			// that leaves a .pending file, and a refusal checks nothing. So the oracle
			// can only be proved at a kill point where the backup is taken and
			// restored: find one instead of assuming it, and fail if none exists.
			// Kill points are probed pcrashBackupScanBatch at a time, in order, and the
			// lowest one that is taken is used: the same kill point a one-by-one scan
			// finds (all earlier batches had none), only the probes run side by side.
			for lo := int64(1); lo <= pcrashBackupScanMax; lo += pcrashBackupScanBatch {
				hi := min(lo+pcrashBackupScanBatch-1, pcrashBackupScanMax)
				found := make([][]string, hi-lo+1)
				t.Run(fmt.Sprintf("kill-points-%d-%d", lo, hi), func(t *testing.T) {
					for killAt := lo; killAt <= hi; killAt++ {
						t.Run(fmt.Sprintf("%d", killAt), func(t *testing.T) {
							t.Parallel()
							found[killAt-lo] = w.checkBackupAfterKilledRotation(t, killAt, 1, func(target string) {
								pcrashExecSQL(t, target, "UPDATE secret_versions SET encrypted_value = randomblob(64) WHERE id = (SELECT MAX(id) FROM secret_versions)")
							})
						})
					}
				})
				if t.Failed() {
					return
				}
				for i, v := range found {
					if len(v) == 0 {
						continue // backup or restore refused here: nothing was checked
					}
					killAt := lo + int64(i)
					if !strings.Contains(v[0], "backup made after a kill") {
						t.Fatalf("kill point %d: unexpected violation: %v", killAt, v)
					}
					if c := w.checkBackupAfterKilledRotation(t, killAt, 1, nil); len(c) > 0 {
						t.Fatalf("control at kill point %d: an undamaged restore must be clean: %v", killAt, c)
					}
					t.Logf("fired as expected at kill point %d: %s", killAt, pcrashTail(v[0]))
					return
				}
			}
			t.Fatalf("no kill point in 1..%d gave a backup that was taken and restored, so the backup-after-kill oracle was never exercised", pcrashBackupScanMax)
		})
		for _, c := range []struct{ name, action, want string }{
			{"I5-rerun-panics", "rerun-panic", "I5"},
			{"I5-rerun-corrupts", "rerun-corrupt", "I5"},
		} {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
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
	})
}

// pcrashBackupScanMax bounds the search for a kill point whose backup is not
// refused; a kill point past the last seam lets the rotation finish.
const pcrashBackupScanMax = 60

// pcrashBackupScanBatch is how many kill points are probed at once. Four matches
// the standard CI runner; a batch past the first taken kill point costs at most
// three extra probes.
const pcrashBackupScanBatch = 4
