//go:build !windows

package encryption_test

// process_crash_recovery_pg_redproof_test.go shows that each oracle of the
// PostgreSQL leg fires on a state that breaks it. Nothing in production changes.
// I3 is broken by the wire proxy committing the DEK sweep's open transaction
// before its second row (the "split"); the others by planting damage in the
// install's own database after the kill. Every plant has an unbroken control.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// pcrashPGRedProof runs op up to the state check with damage planted between the
// operation and the check, and returns the violations.
func (w *pcrashPGWorld) pcrashPGRedProof(t *testing.T, op pcrashOp, split string, killAt int64, plant func(inst *pcrashPGInst)) []string {
	t.Helper()
	ctx := context.Background()
	inst := w.newInstall(t, w.templateDB, w.dir)
	st, err := w.prepare(inst.dir, 1)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	cal := w.calibratePG(t, op)
	after := &pcrashModel{Ledger: op.after(st.before.Ledger, w.seed.Ledger), Roles: cal.ref.Roles, Authz: cal.ref.Authz}
	run, err := w.runOp(inst, op, pcrashPass, killAt, pcrashPGModeKill, split, false)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !run.killed {
		t.Fatalf("the child was not killed (exit %d, seams %d): %s", run.exit, run.seams, pcrashTail(run.output))
	}
	if err := w.srv.quiesce(ctx, inst.db); err != nil {
		t.Fatal(err)
	}
	if plant != nil {
		plant(inst)
	}
	return w.checkAfterDeath(t, op, inst.dir, st, after)
}

func (w *pcrashPGWorld) execSQL(t *testing.T, dbName, stmt string) {
	t.Helper()
	cc, err := pgx.ParseConfig(w.srv.dsn(dbName))
	if err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*cc)
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(context.Background(), stmt); err != nil {
		t.Fatalf("plant %q: %s", stmt, pcrashPGScrub(err, w.srv.password))
	}
}

func TestProcessCrashPGRedProof(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real child processes")
	}
	w := pcrashPGWorldOrSkip(t)
	dek := pcrashOps[0]
	update := pcrashOps[5]
	killUpdate := w.firstSQLSeam(t, update)

	t.Run("control-unbroken-kill-is-clean", func(t *testing.T) {
		if v := w.pcrashPGRedProof(t, dek, "nocommit", 0, nil); len(v) > 0 {
			t.Fatalf("the unsplit sweep killed at the same statement must be clean: %v", v)
		}
	})
	t.Run("I3-split-transaction", func(t *testing.T) {
		pcrashWant(t, w.pcrashPGRedProof(t, dek, "commit", 0, nil), "I3")
	})
	t.Run("control-plain-kill", func(t *testing.T) {
		if v := w.pcrashPGRedProof(t, update, "", killUpdate, nil); len(v) > 0 {
			t.Fatalf("control: an undamaged kill must be clean: %v", v)
		}
	})
	t.Run("I1-database-gone", func(t *testing.T) {
		v := w.pcrashPGRedProof(t, update, "", killUpdate, func(inst *pcrashPGInst) {
			if err := w.srv.dropDB(context.Background(), inst.db); err != nil {
				t.Fatal(err)
			}
		})
		pcrashWant(t, v, "I1")
	})
	t.Run("I2-version-row-lost", func(t *testing.T) {
		v := w.pcrashPGRedProof(t, update, "", killUpdate, func(inst *pcrashPGInst) {
			w.execSQL(t, inst.db, "DELETE FROM secret_versions WHERE id = (SELECT MAX(v.id) FROM secret_versions v JOIN secret_nodes n ON n.id = v.secret_node_id WHERE n.name = 'pcrash-base-2')")
		})
		pcrashWant(t, v, "I2")
	})
	t.Run("I3-half-created-role", func(t *testing.T) {
		v := w.pcrashPGRedProof(t, update, "", killUpdate, func(inst *pcrashPGInst) {
			w.execSQL(t, inst.db, "INSERT INTO roles (name, name_folded, description) VALUES ('pcrash-planted', 'pcrash-planted', 'planted')")
		})
		pcrashWant(t, v, "I3")
	})
	t.Run("I3-undecryptable-version", func(t *testing.T) {
		v := w.pcrashPGRedProof(t, update, "", killUpdate, func(inst *pcrashPGInst) {
			w.execSQL(t, inst.db, "UPDATE secret_versions SET encrypted_value = decode(repeat('ab', 64), 'hex') WHERE id = (SELECT MAX(id) FROM secret_versions)")
		})
		pcrashWant(t, v, "I3")
	})
	t.Run("I4-privilege-widened", func(t *testing.T) {
		v := w.pcrashPGRedProof(t, update, "", killUpdate, func(inst *pcrashPGInst) {
			w.execSQL(t, inst.db, "INSERT INTO user_roles (user_id, role_id, project_id, environment_id) SELECT u.id, r.id, 0, 0 FROM users u, roles r WHERE u.username = 'pcrash-bob' AND r.name = 'admin'")
		})
		pcrashWant(t, v, "I4")
	})
	t.Run("I5-migration-schema-differs", func(t *testing.T) {
		seams := w.migrateSeams(t)
		if v := w.execMigrate(t, seams/2, pcrashPGModeKill, nil); len(v) > 0 {
			t.Fatalf("control: an undamaged migration must be clean: %v", v)
		}
		v := w.execMigrate(t, seams/2, pcrashPGModeKill, func(dbName string) {
			w.execSQL(t, dbName, "DROP TABLE secret_tags")
		})
		pcrashWant(t, v, "I5")
	})
	t.Run("backup-after-kill-control-and-damage", func(t *testing.T) {
		killAt := w.rotateFileSeam(t)
		if refused, v := w.checkBackupAfterKilledRotation(t, killAt, nil); len(v) > 0 {
			t.Fatalf("control: an undamaged restore must be clean (refused=%v): %v", refused, v)
		}
		_, v := w.checkBackupAfterKilledRotation(t, killAt, func(dbName string) {
			w.execSQL(t, dbName, "UPDATE secret_versions SET encrypted_value = decode(repeat('ab', 64), 'hex') WHERE id = (SELECT MAX(id) FROM secret_versions)")
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
			inst := w.newInstall(t, w.templateDB, w.dir)
			st, err := w.prepare(inst.dir, 1)
			if err != nil {
				t.Fatal(err)
			}
			broken := pcrashOp{name: c.action, after: pcrashSame}
			cal := w.calibratePG(t, pcrashOps[6])
			after := &pcrashModel{Ledger: st.before.Ledger.clone(), Roles: cal.ref.Roles, Authz: st.before.Authz}
			m := &pcrashModel{Ledger: st.before.Ledger, Roles: st.before.Roles, Authz: st.before.Authz}
			pcrashWant(t, w.checkRerun(t, broken, inst.dir, pcrashPass, st, after, m), c.want)
		})
	}
}

// firstSQLSeam is the first SQL seam of a calibrated op: a kill point that
// reaches the database and so proves the kill path.
func (w *pcrashPGWorld) firstSQLSeam(t *testing.T, op pcrashOp) int64 {
	t.Helper()
	cal := w.calibratePG(t, op)
	for i, l := range cal.trace {
		if strings.HasPrefix(l, "sql:") {
			return int64(i + 1)
		}
	}
	t.Fatalf("%s has no SQL seam: %v", op.name, cal.trace)
	return 0
}

// rotateFileSeam is the first key-file seam of a DEK rotation, the kill point
// the backup check uses (the SQLite leg picks one the same way).
func (w *pcrashPGWorld) rotateFileSeam(t *testing.T) int64 {
	t.Helper()
	cal := w.calibratePG(t, pcrashOps[0])
	for i, l := range cal.trace {
		if strings.HasPrefix(l, "file:") {
			return int64(i + 1)
		}
	}
	t.Fatalf("no file seam in rotate-dek: %v", cal.trace)
	return 0
}

// TestProcessCrashPGBackendComparison reads the outcome files the two sweeps
// write and compares them at the kill points both backends share: every key-file
// seam, and the last database commit before each key-file seam. A difference
// is logged with the rows, not failed: classifying it is a human call.
func TestProcessCrashPGBackendComparison(t *testing.T) {
	dir := *pcrashFlagOutcomes
	if dir == "" {
		t.Skip("pass -args -pcrash.outcomes=<dir> after running the sweeps")
	}
	type row struct {
		op, label, state string
		killAt           int64
		pending          bool
		violations       string
	}
	load := func(backend string) map[string][]row {
		out := map[string][]row{}
		entries, _ := filepath.Glob(filepath.Join(dir, backend+"-*.tsv"))
		for _, p := range entries {
			b, err := os.ReadFile(p) //nolint:gosec // test-chosen path
			if err != nil {
				t.Fatal(err)
			}
			for line := range strings.Lines(string(b)) {
				f := strings.Split(strings.TrimRight(line, "\n"), "\t")
				if len(f) < 8 || f[2] != pcrashPGModeKill {
					continue
				}
				var k int64
				if _, err := fmt.Sscan(f[3], &k); err != nil {
					t.Fatal(err)
				}
				out[f[1]] = append(out[f[1]], row{op: f[1], killAt: k, label: f[4], state: f[5], pending: f[6] == "true", violations: f[7]})
			}
		}
		return out
	}
	align := func(rows []row) map[string]row {
		byKill := map[int64]row{}
		var maxKill int64
		for _, r := range rows {
			byKill[r.killAt] = r
			maxKill = max(maxKill, r.killAt)
		}
		out := map[string]row{}
		count := map[string]int{}
		var lastCommit *row
		for k := int64(1); k <= maxKill; k++ {
			r, ok := byKill[k]
			if !ok {
				continue
			}
			switch {
			case strings.HasPrefix(r.label, "file:") || (!strings.HasPrefix(r.label, "sql:") && r.label != "clean-run"):
				count[r.label]++
				out[fmt.Sprintf("%s#%d", r.label, count[r.label])] = r
				if lastCommit != nil {
					out[fmt.Sprintf("commit-before:%s#%d", r.label, count[r.label])] = *lastCommit
					lastCommit = nil
				}
			case r.label == "sql:commit" || r.label == "sql:pre:commit":
				c := r
				lastCommit = &c
			}
		}
		return out
	}
	sqlite, pg := load("sqlite"), load("postgres")
	report, err := os.Create(filepath.Join(dir, "comparison.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = report.Close() }()
	diffs, same, onlyOne := 0, 0, 0
	for op, srows := range sqlite {
		pa, sa := align(pg[op]), align(srows)
		for key, s := range sa {
			p, ok := pa[key]
			if !ok {
				onlyOne++
				continue
			}
			if !reflect.DeepEqual(s.state, p.state) || s.pending != p.pending {
				diffs++
				_, _ = fmt.Fprintf(report, "%s\t%s\tsqlite=%s/pending=%v (kill %d)\tpostgres=%s/pending=%v (kill %d)\n", op, key, s.state, s.pending, s.killAt, p.state, p.pending, p.killAt)
			} else {
				same++
			}
		}
	}
	t.Logf("aligned kill points agreeing: %d, differing: %d, present on only one backend: %d; details in comparison.tsv", same, diffs, onlyOne)
}
