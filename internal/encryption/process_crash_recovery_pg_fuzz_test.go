//go:build !windows

package encryption_test

// process_crash_recovery_pg_fuzz_test.go -- FuzzProcessCrashRecoveryPG: the
// PostgreSQL leg of FuzzProcessCrashRecovery. The database is server-side, so
// killing the client leaves committed transactions committed and open ones rolled
// back; the state that can end half done is the client's key files.
//
// Each exec makes a copy of a template install on its own database, runs one
// operation in a child, and acts at the Nth seam (see
// process_crash_recovery_pg_proxy_test.go), in one of two modes:
//
//	kill  SIGKILL the child at the seam, the same death model as the SQLite leg
//	cut   abruptly close the connection at the seam with the child still running
//
// Then it reopens the install against the same database and key files and applies
// the SQLite leg's oracles I1-I5 (checkAfterDeath, checkRerun) unchanged.
//
// What this does not model: a server crash or failover, which no client-side
// harness can provoke; a restart that runs before the server has noticed the dead
// client (quiesce waits for that); and fsync or power loss, as in the SQLite leg.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/restorejournal"
)

// pcrashOutcome is what one exec did, for the comparison between the backends.
type pcrashOutcome struct {
	backend string
	op      string
	mode    string
	killAt  int64
	label   string
	state   string // before, after, same, mix or refused, from pcrashClassify
	pending bool   // dek.key.pending existed right after the death
}

func (o pcrashOutcome) record(violations []string) {
	dir := *pcrashFlagOutcomes
	if dir == "" {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("%s-%d.tsv", o.backend, os.Getpid())), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // test-chosen path
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	v := "-"
	if len(violations) > 0 {
		v = strings.ReplaceAll(strings.Join(violations, " / "), "\t", " ")
		v = strings.ReplaceAll(v, "\n", " ")
	}
	_, _ = fmt.Fprintf(f, "%s\t%s\t%s\t%d\t%s\t%s\t%v\t%s\n", o.backend, o.op, o.mode, o.killAt, o.label, o.state, o.pending, v)
}

func pcrashFindFile(root, name string) string {
	var found string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == name {
			found = p
			return fs.SkipAll
		}
		return nil
	})
	return found
}

// pcrashClassify says which side of the operation the state after death is on,
// using the strongest signal each operation has. It only reads.
func pcrashClassify(ctx context.Context, w *pcrashWorld, op pcrashOp, dir string, st pcrashExecState, after *pcrashModel) string {
	passes := []string{pcrashPass}
	if op.kek {
		passes = []string{pcrashPass, pcrashPass2}
	}
	working := ""
	for _, p := range passes {
		o := pcrashOpenGuarded(dir, p)
		if o.pnc != nil {
			return "refused:panic"
		}
		if o.err != nil {
			continue
		}
		working = p
		o.inst.close()
		break
	}
	if working == "" {
		return "refused"
	}
	o := pcrashOpenGuarded(dir, working)
	if o.pnc != nil || o.err != nil {
		return "refused"
	}
	defer o.inst.close()
	if op.kek {
		if working == pcrashPass {
			return "before"
		}
		return "after"
	}
	if op.name == "rotate-dek" {
		cipher, err := o.inst.ciphertexts()
		if err != nil {
			return "refused"
		}
		changed := 0
		for id, c := range st.cipher {
			if cipher[id] != c {
				changed++
			}
		}
		switch changed {
		case 0:
			return "before"
		case len(st.cipher):
			return "after"
		}
		return "mix"
	}
	m, err := o.inst.observe(ctx, w.seed)
	if err != nil {
		return "refused"
	}
	isBefore, isAfter := pcrashModelEqual(m, st.before), pcrashModelEqual(m, after)
	switch {
	case isBefore && isAfter:
		return "same"
	case isBefore:
		return "before"
	case isAfter:
		return "after"
	}
	return "mix"
}

func (w *pcrashPGWorld) runOp(inst *pcrashPGInst, op pcrashOp, pass string, killAt int64, mode, split string, trace bool) (pcrashPGRun, error) {
	action, args := op.name, []string(nil)
	if len(op.admin) > 0 {
		action, args = "admin", op.admin
	}
	r, err := w.run(inst.dir, pass, action, args, killAt, mode, split, trace)
	if err != nil {
		return r, err
	}
	// Whatever the child did, the install's config points at the real server again.
	return r, inst.restoreYAML()
}

// calibratePG is a clean run of op on a copy of the template.
func (w *pcrashPGWorld) calibratePG(t *testing.T, op pcrashOp) pcrashPGCalibration {
	t.Helper()
	w.calMu.Lock()
	c, ok := w.pgCal[op.name]
	w.calMu.Unlock()
	if ok {
		return c
	}
	inst := w.newInstall(t, w.templateDB, w.dir)
	ctx := context.Background()
	r, err := w.runOp(inst, op, pcrashPass, 0, pcrashPGModeKill, "", true)
	if err != nil {
		t.Fatalf("calibrate %s: %v", op.name, err)
	}
	if r.exit != 0 {
		t.Fatalf("calibrate %s: exit %d: %s", op.name, r.exit, pcrashTail(pcrashPGScrub(errors.New(r.output), w.srv.password)))
	}
	if err := w.srv.quiesce(ctx, inst.db); err != nil {
		t.Fatal(err)
	}
	pass := pcrashPass
	if op.kek {
		pass = pcrashPass2
	}
	o, err := openPCrashInstall(inst.dir, pass)
	if err != nil {
		t.Fatalf("calibrate %s: reopen: %v", op.name, err)
	}
	defer o.close()
	ref, err := o.observe(ctx, w.seed)
	if err != nil {
		t.Fatalf("calibrate %s: observe: %v", op.name, err)
	}
	c = pcrashPGCalibration{seams: r.seams, trace: r.trace, ref: ref}
	w.calMu.Lock()
	defer w.calMu.Unlock()
	w.pgCal[op.name] = c
	w.save(t)
	return c
}

// prepareCached is the before-state of an exec with no extra secrets. It costs a
// full reopen, about 100 seconds through the tunnel, so it runs once per world.
func (w *pcrashPGWorld) prepareCached(t *testing.T) pcrashExecState {
	t.Helper()
	w.calMu.Lock()
	defer w.calMu.Unlock()
	if w.prepared != nil {
		return *w.prepared
	}
	inst := w.newInstall(t, w.templateDB, w.dir)
	st, err := w.prepare(inst.dir, 0)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	w.prepared = &st
	w.save(t)
	return st
}

// pcrashPGKillPoints picks the kill points of a sweep from a clean run's seam
// labels: every key-file seam, every COMMIT and acknowledged commit, and the first
// and last statement of each run of identical statements. maxPer thins only the
// statements in between, evenly, when it is set.
func pcrashPGKillPoints(trace []string, mode string, maxPer int) []int64 {
	essential := func(i int) bool {
		l := trace[i]
		if !strings.HasPrefix(l, "sql:") {
			return mode == pcrashPGModeKill // a key-file seam cannot be cut
		}
		return strings.Contains(l, "commit") || strings.HasPrefix(l, "sql:acked:")
	}
	var must, rest []int64
	for i := range trace {
		switch {
		case essential(i):
			must = append(must, int64(i+1))
		case !strings.HasPrefix(trace[i], "sql:"):
		case mode == pcrashPGModeKill && (i == 0 || trace[i] != trace[i-1] || i == len(trace)-1 || trace[i] != trace[i+1]):
			rest = append(rest, int64(i+1))
		}
	}
	if mode == pcrashPGModeCut {
		// A cut at every commit is the variant's purpose; add one statement inside
		// a transaction, the first write that is not a commit.
		for i, l := range trace {
			if strings.HasPrefix(l, "sql:pre:") && !strings.Contains(l, "commit") {
				rest = append(rest, int64(i+1))
				break
			}
		}
	}
	if maxPer > 0 && len(rest) > maxPer {
		kept := make([]int64, 0, maxPer)
		for n := range maxPer {
			kept = append(kept, rest[n*len(rest)/maxPer])
		}
		rest = kept
	}
	out := append(must, rest...)
	slices.Sort(out)
	return slices.Compact(out)
}

// pcrashOutcomesDone lists the execs the outcome files already record, so a
// sweep can be run again and pick up where a time budget stopped it.
func pcrashOutcomesDone(backend string) map[string]bool {
	done := map[string]bool{}
	if *pcrashFlagOutcomes == "" {
		return done
	}
	paths, _ := filepath.Glob(filepath.Join(*pcrashFlagOutcomes, backend+"-*.tsv"))
	for _, p := range paths {
		b, err := os.ReadFile(p) //nolint:gosec // test-chosen path
		if err != nil {
			continue
		}
		for line := range strings.Lines(string(b)) {
			f := strings.Split(line, "\t")
			if len(f) >= 4 {
				done[f[1]+"|"+f[2]+"|"+f[3]] = true
			}
		}
	}
	return done
}

// pcrashPriority is the order a sweep runs operations in: the ones with key
// material and the permission changes first, restore (by far the most seams) last.
var pcrashPriority = []string{"rotate-dek", "secret-update", "role-grant", "role-revoke", "rotate-kek", "role-create", "secret-create", "backup", "migrate-fresh", "restore"}

// pcrashPGJournalRecover runs the documented recovery if a killed restore left
// its journal; on PostgreSQL the journal is in the key directory (restorejournal.Dir).
func (w *pcrashPGWorld) pcrashPGJournalRecover(t *testing.T, inst *pcrashPGInst) []string {
	t.Helper()
	if pcrashFindFile(inst.dir, restorejournal.FileName) == "" {
		return nil
	}
	r, err := runPCrashChild(inst.dir, pcrashPass, "admin", []string{"restore", "--recover", "--config", "./keyorix.yaml"}, 0)
	if err != nil {
		t.Fatalf("restore --recover: %v", err)
	}
	if r.panicked() {
		return []string{"I1 restore --recover panicked: " + pcrashTail(pcrashPGScrub(errors.New(r.output), w.srv.password))}
	}
	return nil
}

// exec is one input against one operation, returning its violations.
func (w *pcrashPGWorld) exec(t *testing.T, op pcrashOp, killAt int64, stateRaw uint16, mode string) []string {
	t.Helper()
	ctx := context.Background()
	inst := w.newInstall(t, w.templateDB, w.dir)
	var st pcrashExecState
	if stateRaw == 0 {
		st = w.prepareCached(t)
	} else {
		var err error
		if st, err = w.prepare(inst.dir, stateRaw); err != nil {
			t.Fatalf("prepare: %v", err)
		}
	}
	cal := w.calibratePG(t, op)
	after := &pcrashModel{Ledger: op.after(st.before.Ledger, w.seed.Ledger), Roles: cal.ref.Roles, Authz: cal.ref.Authz}
	run, err := w.runOp(inst, op, pcrashPass, killAt, mode, "", false)
	if err != nil {
		t.Fatalf("run %s: %v", op.name, err)
	}
	if err := w.srv.quiesce(ctx, inst.db); err != nil {
		t.Fatal(err)
	}
	if v := w.pcrashPGJournalRecover(t, inst); len(v) > 0 {
		return v
	}
	pcrashRecordStat(op.name+"-pg-"+mode, killAt, run.pcrashChildRun)
	if mode == pcrashPGModeKill && !run.killed && run.exit != 0 {
		return []string{fmt.Sprintf("the operation failed without being killed (exit %d): %s", run.exit, pcrashTail(pcrashPGScrub(errors.New(run.output), w.srv.password)))}
	}
	if run.panicked() {
		return []string{fmt.Sprintf("I1 the operation panicked after a cut connection: %s", pcrashTail(pcrashPGScrub(errors.New(run.output), w.srv.password)))}
	}
	pending := pcrashFindFile(inst.dir, "dek.key.pending") != ""
	state := pcrashClassify(ctx, w.pcrashWorld, op, inst.dir, st, after)
	v := w.checkAfterDeath(t, op, inst.dir, st, after)
	label := run.label
	if label == "" {
		label = "clean-run"
	}
	pcrashOutcome{backend: "postgres", op: op.name, mode: mode, killAt: killAt, label: label, state: state, pending: pending}.record(v)
	return v
}

// execMigrate kills a fresh-install migration and requires the rerun to converge
// on the clean schema, as the SQLite leg's runPCrashMigrate does.
func (w *pcrashPGWorld) execMigrate(t *testing.T, killAt int64, mode string, plant func(dbName string)) (violations []string) {
	t.Helper()
	ctx := context.Background()
	want := w.migrateSchema(t)
	inst := w.newInstall(t, "", w.freshDir)
	run, err := w.runOp(inst, pcrashOp{name: "migrate-fresh", admin: pcrashMigrateArgs}, pcrashPass, killAt, mode, "", false)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := w.srv.quiesce(ctx, inst.db); err != nil {
		t.Fatal(err)
	}
	defer func() {
		state := "converged"
		if len(violations) > 0 {
			state = "mix"
		}
		pcrashOutcome{backend: "postgres", op: "migrate-fresh", mode: mode, killAt: killAt, label: run.label, state: state}.record(violations)
	}()
	pcrashRecordStat("migrate-fresh-pg-"+mode, killAt, run.pcrashChildRun)
	if mode == pcrashPGModeKill && !run.killed && run.exit != 0 {
		return []string{fmt.Sprintf("the migration failed without being killed (exit %d): %s", run.exit, pcrashTail(pcrashPGScrub(errors.New(run.output), w.srv.password)))}
	}
	if run.panicked() {
		return []string{"I1 the migration panicked after a cut connection: " + pcrashTail(pcrashPGScrub(errors.New(run.output), w.srv.password))}
	}
	o := pcrashOpenGuarded(inst.dir, pcrashPass)
	if o.pnc != nil {
		return []string{fmt.Sprintf("I1 open after a killed migration panicked: %v", o.pnc)}
	}
	if o.err != nil {
		if !pcrashExplicitOpenError(o.err) {
			return []string{fmt.Sprintf("I1 open after a killed migration failed without a documented refusal: %s", pcrashPGScrub(o.err, w.srv.password))}
		}
	} else {
		o.inst.close()
	}
	again, err := runPCrashChild(inst.dir, pcrashPass, "admin", pcrashMigrateArgs, 0)
	if err != nil {
		t.Fatalf("rerun migrate: %v", err)
	}
	if again.panicked() || again.killed || again.exit != 0 {
		return []string{fmt.Sprintf("I5 rerun migrate did not complete (exit %d): %s", again.exit, pcrashTail(pcrashPGScrub(errors.New(again.output), w.srv.password)))}
	}
	if err := w.srv.quiesce(ctx, inst.db); err != nil {
		t.Fatal(err)
	}
	if plant != nil {
		plant(inst.db)
	}
	got, err := w.pgSchema(ctx, inst.db)
	if err != nil {
		return []string{"I5 schema after rerun: " + pcrashPGScrub(err, w.srv.password)}
	}
	if got != want {
		return []string{"I5 schema after rerun differs from a clean migration:\n" + pcrashSchemaDiff(got, want)}
	}
	return nil
}

// migrateSchema is a clean fresh-install migration's schema, and its seam count
// is kept for the sweep.
func (w *pcrashPGWorld) migrateSchema(t *testing.T) string {
	t.Helper()
	w.calMu.Lock()
	defer w.calMu.Unlock()
	if w.pgMig != nil {
		return w.pgMigDB
	}
	inst := w.newInstall(t, "", w.freshDir)
	run, err := w.runOp(inst, pcrashOp{name: "migrate-fresh", admin: pcrashMigrateArgs}, pcrashPass, 0, pcrashPGModeKill, "", true)
	if err != nil {
		t.Fatalf("calibrate migrate: %v", err)
	}
	if run.exit != 0 {
		t.Fatalf("calibrate migrate: exit %d: %s", run.exit, pcrashTail(pcrashPGScrub(errors.New(run.output), w.srv.password)))
	}
	ctx := context.Background()
	if err := w.srv.quiesce(ctx, inst.db); err != nil {
		t.Fatal(err)
	}
	schema, err := w.pgSchema(ctx, inst.db)
	if err != nil {
		t.Fatalf("calibrate migrate: schema: %v", pcrashPGScrub(err, w.srv.password))
	}
	w.pgMig = &pcrashPGCalibration{seams: run.seams, trace: run.trace}
	w.pgMigDB = schema
	w.save(t)
	return schema
}

func (w *pcrashPGWorld) migrateSeams(t *testing.T) int64 {
	t.Helper()
	w.migrateSchema(t)
	return w.pgMig.seams
}

func pcrashPGWorldOrSkip(tb testing.TB) *pcrashPGWorld {
	tb.Helper()
	if os.Getenv(envPCrashPGDSN) == "" {
		tb.Skip(envPCrashPGDSN + " not set")
	}
	return buildPCrashPGWorld(tb)
}

// pcrashSelectedOps honours -pcrash.ops, a comma list, so a sweep can be split
// into runs that fit a time budget.
func pcrashSelectedOps() map[string]bool {
	v := *pcrashFlagOps
	if v == "" {
		return nil
	}
	set := map[string]bool{}
	for op := range strings.SplitSeq(v, ",") {
		set[strings.TrimSpace(op)] = true
	}
	return set
}

func TestProcessCrashPGCalibration(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real child processes")
	}
	began := time.Now()
	w := pcrashPGWorldOrSkip(t)
	t.Logf("template ready in %s", time.Since(began).Round(time.Millisecond))
	sel := pcrashSelectedOps()
	w.calMu.Lock()
	cached := maps.Clone(w.pgCal)
	w.calMu.Unlock()
	for _, op := range pcrashOps {
		if sel != nil && !sel[op.name] {
			continue
		}
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			began := time.Now()
			c := w.calibratePG(t, op)
			t.Logf("clean run plus reopen took %s", time.Since(began).Round(time.Millisecond))
			t.Logf("seams=%d trace: %s", c.seams, pcrashTraceSummary(c.trace))
			if _, known := cached[op.name]; known {
				return
			}
			// A second run on a fresh copy shows whether the seam count is stable
			// enough for a kill point to mean the same thing across execs.
			second := w.newInstall(t, w.templateDB, w.dir)
			r2, err := w.runOp(second, op, pcrashPass, 0, pcrashPGModeKill, "", true)
			if err != nil {
				t.Fatalf("second calibration: %v", err)
			}
			t.Logf("seams=%d second=%d equal-trace=%v", c.seams, r2.seams, slices.Equal(c.trace, r2.trace))
		})
	}
	if sel == nil || sel["migrate-fresh"] {
		t.Run("migrate-fresh", func(t *testing.T) {
			t.Parallel()
			t.Logf("seams=%d trace: %s", w.migrateSeams(t), pcrashTraceSummary(w.pgMig.trace))
		})
	}
}

// pcrashTraceSummary collapses runs of one label for reading in a log.
func pcrashTraceSummary(trace []string) string {
	var b strings.Builder
	for i := 0; i < len(trace); {
		j := i
		for j < len(trace) && trace[j] == trace[i] {
			j++
		}
		fmt.Fprintf(&b, "%s×%d ", trace[i], j-i)
		i = j
	}
	return b.String()
}

// TestProcessCrashPGExhaustive kills every operation at every seam it has.
func TestProcessCrashPGExhaustive(t *testing.T) {
	if !*pcrashFlagExhaustive {
		t.Skip("pass -args -pcrash.exhaustive to run the kill-point sweep")
	}
	w := pcrashPGWorldOrSkip(t)
	mode := *pcrashFlagMode
	sel := pcrashSelectedOps()
	began := time.Now()
	done := pcrashOutcomesDone("postgres")
	byName := map[string]pcrashOp{}
	for _, op := range pcrashOps {
		byName[op.name] = op
	}
	start := func(t *testing.T) {
		t.Parallel()
		if b := *pcrashFlagBudget; b > 0 && time.Since(began) > b {
			t.Skip("past -pcrash.budget; the next run resumes here")
		}
	}
	for _, name := range pcrashPriority {
		if sel != nil && !sel[name] {
			continue
		}
		var kills []int64
		if name == "migrate-fresh" {
			w.migrateSeams(t)
			kills = pcrashPGKillPoints(w.pgMig.trace, mode, *pcrashFlagMaxPer)
		} else {
			kills = pcrashPGKillPoints(w.calibratePG(t, byName[name]).trace, mode, *pcrashFlagMaxPer)
		}
		t.Logf("%s: %d kill points in mode %s", name, len(kills), mode)
		for _, killAt := range kills {
			if done[fmt.Sprintf("%s|%s|%d", name, mode, killAt)] {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d", name, killAt), func(t *testing.T) {
				start(t)
				var v []string
				if name == "migrate-fresh" {
					v = w.execMigrate(t, killAt, mode, nil)
				} else {
					v = w.exec(t, byName[name], killAt, 0, mode)
				}
				if len(v) > 0 {
					t.Errorf("%s", strings.Join(v, "; "))
				}
			})
		}
	}
}

// TestProcessCrashSQLiteOutcomes re-runs the SQLite leg at the same seams and
// records each outcome in the same format, for the comparison. It reuses the
// SQLite leg's own world and oracles.
func TestProcessCrashSQLiteOutcomes(t *testing.T) {
	if !*pcrashFlagExhaustive || *pcrashFlagOutcomes == "" {
		t.Skip("pass -args -pcrash.exhaustive -pcrash.outcomes=<dir>")
	}
	w := pcrashWorldFor(t)
	sel := pcrashSelectedOps()
	ctx := context.Background()
	began := time.Now()
	done := pcrashOutcomesDone("sqlite")
	for _, op := range pcrashOps {
		if sel != nil && !sel[op.name] {
			continue
		}
		cal := w.calibrate(t, op)
		for killAt := int64(1); killAt <= cal.seams; killAt++ {
			if done[fmt.Sprintf("%s|kill|%d", op.name, killAt)] {
				continue
			}
			t.Run(fmt.Sprintf("%s/%d", op.name, killAt), func(t *testing.T) {
				t.Parallel()
				if b := *pcrashFlagBudget; b > 0 && time.Since(began) > b {
					t.Skip("past -pcrash.budget; the next run resumes here")
				}
				dir := t.TempDir()
				if err := pcrashCopyTree(w.dir, dir); err != nil {
					t.Fatal(err)
				}
				st, err := w.prepare(dir, uint16(killAt))
				if err != nil {
					t.Fatal(err)
				}
				after := &pcrashModel{Ledger: op.after(st.before.Ledger, w.seed.Ledger), Roles: cal.ref.Roles, Authz: cal.ref.Authz}
				run, err := op.run(dir, pcrashPass, killAt)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(filepath.Join(dir, ".keyorix-restore-journal.json")); err == nil {
					if _, err := runPCrashChild(dir, pcrashPass, "admin", []string{"restore", "--recover", "--config", "./keyorix.yaml"}, 0); err != nil {
						t.Fatal(err)
					}
				}
				pending := pcrashFindFile(dir, "dek.key.pending") != ""
				state := pcrashClassify(ctx, w, op, dir, st, after)
				v := w.checkAfterDeath(t, op, dir, st, after)
				pcrashOutcome{backend: "sqlite", op: op.name, mode: "kill", killAt: killAt, label: run.label, state: state, pending: pending}.record(v)
				if len(v) > 0 {
					t.Errorf("%s", strings.Join(v, "; "))
				}
			})
		}
	}
}

// checkBackupAfterKilledRotation is the SQLite leg's check of the same name on
// PostgreSQL: kill a DEK rotation, back up with no restart in between, restore
// the archive onto the killed install, then onto a clean host.
//
// It reports whether the known clean-host refusal (issue #4058) happened.
func (w *pcrashPGWorld) checkBackupAfterKilledRotation(t *testing.T, killAt int64, plant func(dbName string)) (bool, []string) {
	t.Helper()
	ctx := context.Background()
	op := pcrashOps[0]
	inst := w.newInstall(t, w.templateDB, w.dir)
	st, err := w.prepare(inst.dir, uint16(killAt))
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	run, err := w.runOp(inst, op, pcrashPass, killAt, pcrashPGModeKill, "", false)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := w.srv.quiesce(ctx, inst.db); err != nil {
		t.Fatal(err)
	}
	pcrashRecordStat("backup-after-rotate-pg", killAt, run.pcrashChildRun)
	backupArgs := []string{"backup", "--config", "./keyorix.yaml", "--output", "./post.tar.gz"}
	b, err := runPCrashChild(inst.dir, pcrashPass, "admin", backupArgs, 0)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if b.panicked() {
		return false, []string{"backup after a killed rotation panicked: " + pcrashTail(pcrashPGScrub(errors.New(b.output), w.srv.password))}
	}
	if b.exit != 0 {
		t.Logf("outcome: backup refused (killed at %s): %s", run.label, pcrashTail(pcrashPGScrub(errors.New(b.output), w.srv.password)))
		return false, nil
	}
	archive, err := os.ReadFile(filepath.Join(inst.dir, "post.tar.gz"))
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	restoreArgs := []string{"restore", "--config", "./keyorix.yaml", "--input", "./post.tar.gz", "--overwrite-existing", "--allow-rollback"}
	if err := w.srv.quiesce(ctx, inst.db); err != nil {
		t.Fatal(err)
	}
	r, err := runPCrashChild(inst.dir, pcrashPass, "admin", restoreArgs, 0)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if r.panicked() {
		return false, []string{"restore of the post-kill backup panicked: " + pcrashTail(pcrashPGScrub(errors.New(r.output), w.srv.password))}
	}
	if r.exit != 0 {
		t.Logf("outcome: restore onto the killed install refused (killed at %s): %s", run.label, pcrashTail(pcrashPGScrub(errors.New(r.output), w.srv.password)))
		return false, nil
	}
	if plant != nil {
		plant(inst.db)
	}
	t.Logf("outcome: backup and restore both succeeded (killed at %s)", run.label)
	o := pcrashOpenGuarded(inst.dir, pcrashPass)
	if o.pnc != nil || o.err != nil {
		return false, []string{fmt.Sprintf("backup made after a kill restored but the install will not open: panic=%v err=%s", o.pnc, pcrashPGScrub(o.err, w.srv.password))}
	}
	m, err := o.inst.observe(ctx, w.seed)
	o.inst.close()
	if err != nil {
		return false, []string{"backup made after a kill restored but a secret is unreadable: " + pcrashPGScrub(err, w.srv.password)}
	}
	if !reflect.DeepEqual(m.Ledger, st.before.Ledger) {
		return false, []string{fmt.Sprintf("backup made after a kill restored a different ledger: have %v, want %v", m.Ledger, st.before.Ledger)}
	}
	if plant != nil {
		return false, nil
	}
	return w.checkCleanHostRestore(t, archive, run.label, st)
}

// checkCleanHostRestore is the replacement-host half; see issue #4058.
func (w *pcrashPGWorld) checkCleanHostRestore(t *testing.T, archive []byte, label string, st pcrashExecState) (bool, []string) {
	t.Helper()
	ctx := context.Background()
	target := w.newInstall(t, w.templateDB, w.dir)
	if err := os.WriteFile(filepath.Join(target.dir, "post.tar.gz"), archive, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := runPCrashChild(target.dir, pcrashPass, "admin", []string{"restore", "--config", "./keyorix.yaml", "--input", "./post.tar.gz", "--overwrite-existing", "--allow-rollback"}, 0)
	if err != nil {
		t.Fatalf("clean-host restore: %v", err)
	}
	if r.panicked() {
		return false, []string{"clean-host restore panicked: " + pcrashTail(pcrashPGScrub(errors.New(r.output), w.srv.password))}
	}
	if r.exit != 0 {
		if strings.Contains(r.output, "key file(s) but this config") {
			t.Logf("finding: clean-host restore refused (killed at %s) (#4058)", label)
			return true, nil
		}
		t.Logf("outcome: clean-host restore refused for another reason (killed at %s): %s", label, pcrashTail(pcrashPGScrub(errors.New(r.output), w.srv.password)))
		return false, nil
	}
	t.Logf("outcome: clean-host restore succeeded (killed at %s)", label)
	if err := w.srv.quiesce(ctx, target.db); err != nil {
		t.Fatal(err)
	}
	o := pcrashOpenGuarded(target.dir, pcrashPass)
	if o.pnc != nil || o.err != nil {
		return false, []string{fmt.Sprintf("clean-host restore succeeded but the install will not open (killed at %s): panic=%v err=%s", label, o.pnc, pcrashPGScrub(o.err, w.srv.password))}
	}
	defer o.inst.close()
	m, err := o.inst.observe(ctx, w.seed)
	if err != nil {
		return false, []string{fmt.Sprintf("clean-host restore succeeded but a secret is unreadable (killed at %s): %s", label, pcrashPGScrub(err, w.srv.password))}
	}
	if !reflect.DeepEqual(m.Ledger, st.before.Ledger) {
		return false, []string{fmt.Sprintf("clean-host restore gave a different ledger (killed at %s): have %v, want %v", label, m.Ledger, st.before.Ledger)}
	}
	return false, nil
}

// TestProcessCrashPGBackupAfterKilledRotation runs that check at every rotation seam.
func TestProcessCrashPGBackupAfterKilledRotation(t *testing.T) {
	if !*pcrashFlagExhaustive {
		t.Skip("pass -args -pcrash.exhaustive to kill a rotation at every seam and back up")
	}
	w := pcrashPGWorldOrSkip(t)
	cal := w.calibratePG(t, pcrashOps[0])
	for killAt := int64(1); killAt <= cal.seams; killAt++ {
		t.Run(fmt.Sprintf("%d", killAt), func(t *testing.T) {
			t.Parallel()
			if _, v := w.checkBackupAfterKilledRotation(t, killAt, nil); len(v) > 0 {
				t.Errorf("%s", strings.Join(v, "; "))
			}
		})
	}
}

func FuzzProcessCrashRecoveryPG(f *testing.F) {
	for i := range len(pcrashOps) + 1 {
		f.Add(uint8(i), uint16(3), uint16(i)*7, uint8(i))
	}
	if os.Getenv(envPCrashPGDSN) == "" {
		// Seed execs still have to pass; without a server there is nothing to do.
		f.Skip(envPCrashPGDSN + " not set")
	}
	w := buildPCrashPGWorld(f)
	f.Fuzz(func(t *testing.T, opRaw uint8, killRaw, stateRaw uint16, modeRaw uint8) {
		mode := pcrashPGModeKill
		if modeRaw%4 == 3 {
			mode = pcrashPGModeCut
		}
		opIdx := int(opRaw) % (len(pcrashOps) + 1)
		if opIdx == len(pcrashOps) {
			seams := w.migrateSeams(t)
			killAt := 1 + int64(killRaw)%(seams+1)
			if v := w.execMigrate(t, killAt, mode, nil); len(v) > 0 {
				t.Fatalf("op=migrate-fresh mode=%s killAt=%d (of %d seams): %s", mode, killAt, seams, strings.Join(v, "; "))
			}
			return
		}
		op := pcrashOps[opIdx]
		cal := w.calibratePG(t, op)
		killAt := 1 + int64(killRaw)%(cal.seams+1)
		if v := w.exec(t, op, killAt, stateRaw, mode); len(v) > 0 {
			t.Fatalf("op=%s mode=%s killAt=%d state=%d (of %d seams): %s", op.name, mode, killAt, stateRaw, cal.seams, strings.Join(v, "; "))
		}
	})
}
