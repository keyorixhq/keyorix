//go:build !windows

package encryption_test

// process_crash_recovery_fuzz_test.go -- FuzzProcessCrashRecovery: run one
// multi-step write in a real child process, SIGKILL it at the Nth write seam
// (see process_crash_recovery_child_test.go), then reopen the install the way a
// restart would and check the state.
//
// Invariants, each reported under its own name:
//
//	I1 the install opens, or refuses with a documented explicit error; never a panic.
//	I2 every secret written before the operation reads back with its value.
//	I3 the state is wholly the before or the after model, never a mix.
//	I4 the authorization probes match the before or the after model.
//	I5 rerunning the operation completes or refuses explicitly and corrupts nothing.
//
// What this does not model: SIGKILL stops the process and leaves the page cache
// to the kernel, so a green run says nothing about fsync or power loss.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	pcrashChildDeadline = 3 * time.Minute
	envPCrashStats      = "KEYORIX_PCRASH_STATS" // optional dir: one TSV line per exec
)

// pcrashOp is one operation under test. The after model is the before model
// with after applied to the ledger, plus the roles and authorization a clean
// reference run of the operation produced.
type pcrashOp struct {
	name  string
	admin []string // admin command line; empty means a core action named name
	after func(before, seed pcrashLedger) pcrashLedger
	// again is the ledger a clean rerun adds on top of a completed first run;
	// nil means a completed operation's rerun changes nothing.
	again func(after pcrashLedger) pcrashLedger
	kek   bool // the operation changes the passphrase
	// passes overrides the passphrases tried after a kill; only the red-proof sets it.
	passes []string
}

func pcrashSame(before, _ pcrashLedger) pcrashLedger { return before.clone() }

var pcrashOps = []pcrashOp{
	{name: "rotate-dek", admin: []string{"encryption", "rotate", "--confirm", "--config", "./keyorix.yaml"}, after: pcrashSame},
	{
		name:  "rotate-kek",
		admin: []string{"encryption", "rotate-kek", "--confirm", "--new-passphrase-file", "./newpass", "--config", "./keyorix.yaml"},
		after: pcrashSame, kek: true,
	},
	{name: "backup", admin: []string{"backup", "--config", "./keyorix.yaml", "--output", "./b.tar.gz"}, after: pcrashSame},
	{
		name:  "restore",
		admin: []string{"restore", "--config", "./keyorix.yaml", "--input", "./archive.tar.gz", "--overwrite-existing", "--allow-rollback"},
		after: func(_, seed pcrashLedger) pcrashLedger { return seed.clone() },
	},
	{name: "secret-create", after: func(before, _ pcrashLedger) pcrashLedger {
		l := before.clone()
		l[pcrashNewName] = []string{pcrashNewValue}
		return l
	}},
	{name: "secret-update", after: pcrashAppendUpdate, again: func(after pcrashLedger) pcrashLedger {
		return pcrashAppendUpdate(after, nil)
	}},
	{name: "role-grant", after: pcrashSame},
	{name: "role-revoke", after: pcrashSame},
	{name: "role-create", after: pcrashSame},
}

func pcrashAppendUpdate(before, _ pcrashLedger) pcrashLedger {
	l := before.clone()
	l[pcrashUpdName] = append(l[pcrashUpdName], pcrashUpdValue)
	return l
}

// pcrashChildRun is one child process's outcome.
type pcrashChildRun struct {
	killed bool
	exit   int
	seams  int64
	label  string
	output string
}

func (r pcrashChildRun) panicked() bool {
	return strings.Contains(r.output, "panic:") || strings.Contains(r.output, "fatal error:")
}

func runPCrashChild(dir, pass, action string, args []string, killAt int64) (pcrashChildRun, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pcrashChildDeadline)
	defer cancel()
	bin, err := os.Executable()
	if err != nil {
		return pcrashChildRun{}, err
	}
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return pcrashChildRun{}, err
	}
	resultFile, err := os.CreateTemp("", "pcrash-result-*")
	if err != nil {
		return pcrashChildRun{}, err
	}
	_ = resultFile.Close()
	defer func() { _ = os.Remove(resultFile.Name()) }()

	cmd := exec.CommandContext(ctx, bin, "-test.run=^TestProcessCrashChild$") //nolint:gosec // this test binary, re-executed
	cmd.Dir = dir
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = []string{
		"HOME=" + dir,
		"PATH=/usr/bin:/bin",
		"TMPDIR=" + os.TempDir(),
		envPCrashChild + "=" + action,
		fmt.Sprintf("%s=%d", envPCrashKillAt, killAt),
		envPCrashResult + "=" + resultFile.Name(),
		envPCrashArgs + "=" + string(argsJSON),
		envPCrashPass + "=" + pass,
	}
	out, runErr := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return pcrashChildRun{output: string(out)}, fmt.Errorf("child %s %v passed its %s deadline: %s", action, args, pcrashChildDeadline, pcrashTail(string(out)))
	}
	r := pcrashChildRun{output: string(out)}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
		r.killed = ws.Signaled() && ws.Signal() == syscall.SIGKILL
		r.exit = ws.ExitStatus()
	}
	if _, isExit := errors.AsType[*exec.ExitError](runErr); runErr != nil && !isExit {
		return r, fmt.Errorf("start child: %w", runErr)
	}
	if b, err := os.ReadFile(resultFile.Name()); err == nil && len(b) > 0 {
		var res pcrashChildResult
		if json.Unmarshal(b, &res) == nil {
			r.seams, r.label = res.Seams, res.Label
		}
	}
	return r, nil
}

func pcrashTail(s string) string {
	const limit = 1200
	if len(s) > limit {
		return "..." + s[len(s)-limit:]
	}
	return s
}

func pcrashCopyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if !d.Type().IsRegular() {
			return nil // sockets and lock leftovers are not part of an install
		}
		b, err := os.ReadFile(p) //nolint:gosec // test-generated path
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, info.Mode().Perm())
	})
}

// pcrashCalibration is a clean run of an operation on the unmodified template.
type pcrashCalibration struct {
	seams int64
	ref   *pcrashModel
}

// pcrashWorld is one test's template install. Fuzz workers each build their own,
// so a run never shares a mutable directory with another process.
type pcrashWorld struct {
	dir   string // a populated install
	fresh string // keys and config, no schema: the migration target
	seed  pcrashSeed

	mu        sync.Mutex
	cal       map[string]pcrashCalibration
	migSeams  int64
	migSchema string
}

func buildPCrashWorld() (*pcrashWorld, error) {
	dir, err := os.MkdirTemp("", "pcrash-template-*")
	if err != nil {
		return nil, err
	}
	fresh, err := os.MkdirTemp("", "pcrash-fresh-*")
	if err != nil {
		return nil, err
	}
	for _, args := range [][]string{
		{"init", "--dev", "--config", "./keyorix.yaml"},
		{"encryption", "init", "--config", "./keyorix.yaml"},
		pcrashMigrateArgs,
	} {
		if args[0] == pcrashMigrateArgs[0] {
			// Everything up to here is the migration target: keys, no schema.
			if err := pcrashCopyTree(dir, fresh); err != nil {
				return nil, err
			}
		}
		r, err := runPCrashChild(dir, pcrashPass, "admin", args, 0)
		if err != nil {
			return nil, err
		}
		if r.exit != 0 {
			return nil, fmt.Errorf("template: admin %v exited %d: %s", args, r.exit, pcrashTail(r.output))
		}
	}
	r, err := runPCrashChild(dir, pcrashPass, "seed", nil, 0)
	if err != nil {
		return nil, err
	}
	if r.exit != 0 {
		return nil, fmt.Errorf("template: seed exited %d: %s", r.exit, pcrashTail(r.output))
	}
	if r, err = runPCrashChild(dir, pcrashPass, "admin", []string{"backup", "--config", "./keyorix.yaml", "--output", "./archive.tar.gz"}, 0); err != nil {
		return nil, err
	}
	if r.exit != 0 {
		return nil, fmt.Errorf("template: backup exited %d: %s", r.exit, pcrashTail(r.output))
	}
	if err := os.WriteFile(filepath.Join(dir, "newpass"), []byte(pcrashPass2), 0o600); err != nil {
		return nil, err
	}
	seed, err := readPCrashSeed(dir)
	if err != nil {
		return nil, err
	}
	return &pcrashWorld{dir: dir, fresh: fresh, seed: seed, cal: map[string]pcrashCalibration{}}, nil
}

var pcrashMigrateArgs = []string{"migrate", "--config", "./keyorix.yaml"}

// pcrashSchema is the sorted text of the database's schema objects.
func pcrashSchema(dir string) (string, error) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "keyorix.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return "", err
	}
	defer func() { _ = db.Close() }()
	var ic string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&ic); err != nil {
		return "", fmt.Errorf("integrity_check: %w", err)
	}
	if ic != "ok" {
		return "", fmt.Errorf("integrity_check: %s", ic)
	}
	rows, err := db.Query("SELECT type, name, COALESCE(sql, '') FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")
	if err != nil {
		return "", err
	}
	defer func() { _ = rows.Close() }()
	var b strings.Builder
	for rows.Next() {
		var typ, name, text string
		if err := rows.Scan(&typ, &name, &text); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s %s %s\n", typ, name, text)
	}
	return b.String(), rows.Err()
}

// calibrateMigrate is a clean fresh-install migration: its seam count and schema.
func (w *pcrashWorld) calibrateMigrate(t *testing.T) (int64, string) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.migSchema != "" {
		return w.migSeams, w.migSchema
	}
	dir := t.TempDir()
	if err := pcrashCopyTree(w.fresh, dir); err != nil {
		t.Fatalf("copy fresh install: %v", err)
	}
	r, err := runPCrashChild(dir, pcrashPass, "admin", pcrashMigrateArgs, 0)
	if err != nil {
		t.Fatalf("calibrate migrate: %v", err)
	}
	if r.exit != 0 {
		t.Fatalf("calibrate migrate: exit %d: %s", r.exit, pcrashTail(r.output))
	}
	schema, err := pcrashSchema(dir)
	if err != nil {
		t.Fatalf("calibrate migrate: schema: %v", err)
	}
	w.migSeams, w.migSchema = r.seams, schema
	return r.seams, schema
}

// runPCrashMigrate kills a fresh-install migration at killAt. There are no
// secrets to compare, so it checks I1 and I5: the install opens or refuses
// explicitly, and rerunning the migration converges on the clean schema.
//
// plant, when set, damages the schema before the comparison; only the red-proof uses it.
func (w *pcrashWorld) runPCrashMigrate(t *testing.T, killAt int64, plant func(dir string)) []string {
	t.Helper()
	_, want := w.calibrateMigrate(t)
	dir := t.TempDir()
	if err := pcrashCopyTree(w.fresh, dir); err != nil {
		t.Fatalf("copy fresh install: %v", err)
	}
	run, err := runPCrashChild(dir, pcrashPass, "admin", pcrashMigrateArgs, killAt)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pcrashRecordStat("migrate-fresh", killAt, run)
	if !run.killed && run.exit != 0 {
		return []string{fmt.Sprintf("the migration failed without being killed (exit %d): %s", run.exit, pcrashTail(run.output))}
	}
	o := pcrashOpenGuarded(dir, pcrashPass)
	if o.pnc != nil {
		return []string{fmt.Sprintf("I1 open after a killed migration panicked: %v", o.pnc)}
	}
	if o.err != nil {
		if !pcrashExplicitOpenError(o.err) {
			return []string{fmt.Sprintf("I1 open after a killed migration failed without a documented refusal: %v", o.err)}
		}
	} else {
		o.inst.close()
	}
	again, err := runPCrashChild(dir, pcrashPass, "admin", pcrashMigrateArgs, 0)
	if err != nil {
		t.Fatalf("rerun migrate: %v", err)
	}
	if again.panicked() || again.killed || again.exit != 0 {
		return []string{fmt.Sprintf("I5 rerun migrate did not complete (exit %d): %s", again.exit, pcrashTail(again.output))}
	}
	if plant != nil {
		plant(dir)
	}
	got, err := pcrashSchema(dir)
	if err != nil {
		return []string{"I5 schema after rerun: " + err.Error()}
	}
	if got != want {
		return []string{"I5 schema after rerun differs from a clean migration:\n" + pcrashSchemaDiff(got, want)}
	}
	return nil
}

func pcrashSchemaDiff(got, want string) string {
	gotLines, wantLines := strings.Split(got, "\n"), strings.Split(want, "\n")
	var out []string
	for _, l := range wantLines {
		if !slices.Contains(gotLines, l) {
			out = append(out, "- "+l)
		}
	}
	for _, l := range gotLines {
		if !slices.Contains(wantLines, l) {
			out = append(out, "+ "+l)
		}
	}
	return pcrashTail(strings.Join(out, "\n"))
}

func (op pcrashOp) run(dir, pass string, killAt int64) (pcrashChildRun, error) {
	if len(op.admin) > 0 {
		return runPCrashChild(dir, pass, "admin", op.admin, killAt)
	}
	return runPCrashChild(dir, pass, op.name, nil, killAt)
}

// calibrate runs op once, cleanly, on a template copy: how many seams it has and
// what the after state's roles and decisions are.
func (w *pcrashWorld) calibrate(t *testing.T, op pcrashOp) pcrashCalibration {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if c, ok := w.cal[op.name]; ok {
		return c
	}
	dir := t.TempDir()
	if err := pcrashCopyTree(w.dir, dir); err != nil {
		t.Fatalf("copy template: %v", err)
	}
	r, err := op.run(dir, pcrashPass, 0)
	if err != nil {
		t.Fatalf("calibrate %s: %v", op.name, err)
	}
	if r.exit != 0 {
		t.Fatalf("calibrate %s: exit %d: %s", op.name, r.exit, pcrashTail(r.output))
	}
	pass := pcrashPass
	if op.kek {
		pass = pcrashPass2
	}
	inst, err := openPCrashInstall(dir, pass)
	if err != nil {
		t.Fatalf("calibrate %s: reopen: %v", op.name, err)
	}
	defer inst.close()
	ref, err := inst.observe(context.Background(), w.seed)
	if err != nil {
		t.Fatalf("calibrate %s: observe: %v", op.name, err)
	}
	c := pcrashCalibration{seams: r.seams, ref: ref}
	w.cal[op.name] = c
	return c
}

// pcrashExecState is what one fuzz input adds to the template and observes.
type pcrashExecState struct {
	before *pcrashModel
	cipher map[uint]string
}

func (w *pcrashWorld) prepare(dir string, stateRaw uint16) (pcrashExecState, error) {
	inst, err := openPCrashInstall(dir, pcrashPass)
	if err != nil {
		return pcrashExecState{}, fmt.Errorf("open before the kill: %w", err)
	}
	defer inst.close()
	ctx := context.Background()
	for n := range int(stateRaw % 3) {
		name := fmt.Sprintf("pcrash-extra-%d", n)
		values := make([]string, int(stateRaw>>4)%3+1)
		for v := range values {
			values[v] = fmt.Sprintf("%s-%d-%x", name, v, stateRaw)
		}
		if err := addPCrashSecret(ctx, inst.core, w.seed, name, values); err != nil {
			return pcrashExecState{}, err
		}
	}
	before, err := inst.observe(ctx, w.seed)
	if err != nil {
		return pcrashExecState{}, fmt.Errorf("observe before the kill: %w", err)
	}
	cipher, err := inst.ciphertexts()
	if err != nil {
		return pcrashExecState{}, err
	}
	return pcrashExecState{before: before, cipher: cipher}, nil
}

// pcrashOpened is the result of one guarded reopen.
type pcrashOpened struct {
	inst *pcrashInstall
	err  error
	pnc  any
}

func pcrashOpenGuarded(dir, pass string) (o pcrashOpened) {
	defer func() {
		if r := recover(); r != nil {
			o = pcrashOpened{pnc: r}
		}
	}()
	inst, err := openPCrashInstall(dir, pass)
	return pcrashOpened{inst: inst, err: err}
}

// pcrashExplicitOpenError reports whether err is a refusal an operator is told
// how to resolve, as opposed to an unexplained failure to open. The list is the
// set of refusals with documented recovery steps; anything else fails I1.
func pcrashExplicitOpenError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "admin restore --recover") ||
		strings.Contains(msg, "key file consistency") ||
		errors.Is(err, errPCrashKey)
}

func pcrashModelEqual(a, b *pcrashModel) bool {
	return reflect.DeepEqual(a.Ledger, b.Ledger) && reflect.DeepEqual(a.Roles, b.Roles) && reflect.DeepEqual(a.Authz, b.Authz)
}

func pcrashAuthzDiff(got, want map[string]bool) []string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(want)) {
		if got[k] != want[k] {
			out = append(out, fmt.Sprintf("%s=%v(want %v)", k, got[k], want[k]))
		}
	}
	return out
}

// runPCrashExec is the whole check for one input; it returns the violations.
func (w *pcrashWorld) runPCrashExec(t *testing.T, op pcrashOp, killAt int64, stateRaw uint16) []string {
	t.Helper()
	dir := t.TempDir()
	if err := pcrashCopyTree(w.dir, dir); err != nil {
		t.Fatalf("copy template: %v", err)
	}
	st, err := w.prepare(dir, stateRaw)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	cal := w.calibrate(t, op)
	after := &pcrashModel{Ledger: op.after(st.before.Ledger, w.seed.Ledger), Roles: cal.ref.Roles, Authz: cal.ref.Authz}

	run, err := op.run(dir, pcrashPass, killAt)
	if err != nil {
		t.Fatalf("run %s: %v", op.name, err)
	}
	pcrashRecordStat(op.name, killAt, run)
	if !run.killed && run.exit != 0 {
		return []string{fmt.Sprintf("the operation failed without being killed (exit %d): %s", run.exit, pcrashTail(run.output))}
	}
	return w.checkAfterDeath(t, op, dir, st, after)
}

func (w *pcrashWorld) checkAfterDeath(t *testing.T, op pcrashOp, dir string, st pcrashExecState, after *pcrashModel) []string {
	t.Helper()
	ctx := context.Background()
	var v []string

	// Documented recovery for a killed restore, the only one the operator runs.
	journal := filepath.Join(dir, ".keyorix-restore-journal.json")
	if _, err := os.Stat(journal); err == nil {
		r, err := runPCrashChild(dir, pcrashPass, "admin", []string{"restore", "--recover", "--config", "./keyorix.yaml"}, 0)
		if err != nil {
			t.Fatalf("restore --recover: %v", err)
		}
		if r.panicked() {
			return []string{"I1 restore --recover panicked: " + pcrashTail(r.output)}
		}
	}

	passes := []string{pcrashPass}
	if op.kek {
		passes = []string{pcrashPass, pcrashPass2}
	}
	if op.passes != nil {
		passes = op.passes
	}
	// Each attempt closes before the next: an open install holds the key lock.
	var working []string
	for _, p := range passes {
		o := pcrashOpenGuarded(dir, p)
		if o.pnc != nil {
			return []string{fmt.Sprintf("I1 reopen panicked: %v", o.pnc)}
		}
		if o.err != nil && !pcrashExplicitOpenError(o.err) {
			return []string{fmt.Sprintf("I1 reopen failed without a documented refusal: %v", o.err)}
		}
		if o.err == nil {
			working = append(working, p)
			o.inst.close()
		}
	}
	if op.kek && len(working) != 1 {
		v = append(v, fmt.Sprintf("I3 rotate-kek: %d passphrases open the install after the kill, want exactly 1", len(working)))
	}
	if len(working) == 0 {
		return append(v, "I1 no passphrase opens the install after the kill")
	}
	reopened := pcrashOpenGuarded(dir, working[0])
	if reopened.pnc != nil || reopened.err != nil {
		return append(v, fmt.Sprintf("I1 reopen with the working passphrase failed: panic=%v err=%v", reopened.pnc, reopened.err))
	}
	opened := []pcrashOpened{reopened}
	defer func() {
		for _, o := range opened {
			o.inst.close()
		}
	}()
	// Before the read path, so a half-rotated set is named as that and not as
	// the decrypt failure it also causes.
	if op.name == "rotate-dek" {
		cipher, err := opened[0].inst.ciphertexts()
		if err != nil {
			return append(v, "I3 read ciphertexts: "+err.Error())
		}
		changed := 0
		for id, c := range st.cipher {
			if cipher[id] != c {
				changed++
			}
		}
		if changed != 0 && changed != len(st.cipher) {
			return append(v, fmt.Sprintf("I3 rotate-dek left a half-rotated set: %d of %d stored versions changed", changed, len(st.cipher)))
		}
	}
	m, err := opened[0].inst.observe(ctx, w.seed)
	if err != nil {
		return append(v, "I3 observe after the kill: "+err.Error())
	}
	ledgerBefore, ledgerAfter := reflect.DeepEqual(m.Ledger, st.before.Ledger), reflect.DeepEqual(m.Ledger, after.Ledger)
	// A completed operation may legitimately replace values (restore, update).
	if !ledgerAfter {
		for name, values := range st.before.Ledger {
			if !reflect.DeepEqual(m.Ledger[name], values) {
				v = append(v, fmt.Sprintf("I2 secret %q changed: have %q, want %q", name, m.Ledger[name], values))
			}
		}
	}
	if !ledgerBefore && !ledgerAfter {
		v = append(v, fmt.Sprintf("I3 ledger is neither before nor after: have %v, before %v, after %v", m.Ledger, st.before.Ledger, after.Ledger))
	}
	if !reflect.DeepEqual(m.Roles, st.before.Roles) && !reflect.DeepEqual(m.Roles, after.Roles) {
		v = append(v, fmt.Sprintf("I3 roles are neither before nor after: have %v", m.Roles))
	}
	if !reflect.DeepEqual(m.Authz, st.before.Authz) && !reflect.DeepEqual(m.Authz, after.Authz) {
		v = append(v, fmt.Sprintf("I4 authorization is neither before nor after: vs before %v, vs after %v", pcrashAuthzDiff(m.Authz, st.before.Authz), pcrashAuthzDiff(m.Authz, after.Authz)))
	}
	for _, o := range opened {
		o.inst.close()
	}
	opened = nil
	if len(v) > 0 {
		return v
	}
	return w.checkRerun(t, op, dir, working[0], st, after, m)
}

// checkRerun is I5: run the interrupted operation again and require a clean
// completion or an explicit refusal, leaving an allowed state.
func (w *pcrashWorld) checkRerun(t *testing.T, op pcrashOp, dir, pass string, st pcrashExecState, after, afterKill *pcrashModel) []string {
	t.Helper()
	if op.kek {
		if err := os.WriteFile(filepath.Join(dir, "newpass"), []byte(pcrashPass3), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := op.run(dir, pass, 0)
	if err != nil {
		t.Fatalf("rerun %s: %v", op.name, err)
	}
	if r.panicked() || r.killed {
		return []string{"I5 rerun did not end cleanly: " + pcrashTail(r.output)}
	}
	if r.exit != 0 && strings.TrimSpace(r.output) == "" {
		return []string{fmt.Sprintf("I5 rerun refused with exit %d and no explanation", r.exit)}
	}
	finalPass := pass
	if op.kek && r.exit == 0 {
		finalPass = pcrashPass3
	}
	o := pcrashOpenGuarded(dir, finalPass)
	if o.pnc != nil {
		return []string{fmt.Sprintf("I5 reopen after rerun panicked: %v", o.pnc)}
	}
	if o.err != nil {
		return []string{fmt.Sprintf("I5 reopen after rerun failed: %v", o.err)}
	}
	defer o.inst.close()
	m, err := o.inst.observe(context.Background(), w.seed)
	if err != nil {
		return []string{"I5 observe after rerun: " + err.Error()}
	}
	allowed := []pcrashLedger{st.before.Ledger, after.Ledger, afterKill.Ledger}
	if op.again != nil {
		allowed = append(allowed, op.again(after.Ledger), op.again(afterKill.Ledger))
	}
	if !slices.ContainsFunc(allowed, func(l pcrashLedger) bool { return reflect.DeepEqual(m.Ledger, l) }) {
		return []string{fmt.Sprintf("I5 ledger after rerun is not an allowed state: %v", m.Ledger)}
	}
	if r.exit == 0 && !reflect.DeepEqual(m.Roles, after.Roles) {
		return []string{fmt.Sprintf("I5 roles after a completed rerun differ from the after model: %v", m.Roles)}
	}
	return nil
}

func pcrashRecordStat(op string, killAt int64, r pcrashChildRun) {
	dir := os.Getenv(envPCrashStats)
	if dir == "" {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("%d.tsv", os.Getpid())), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // test-chosen path
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintf(f, "%s\t%d\t%v\t%s\n", op, killAt, r.killed, r.label)
}

// pcrashWorldFor builds a template for tb and removes it when tb ends.
func pcrashWorldFor(tb testing.TB) *pcrashWorld {
	tb.Helper()
	w, err := buildPCrashWorld()
	if err != nil {
		tb.Fatalf("build template: %v", err)
	}
	tb.Cleanup(func() {
		_ = os.RemoveAll(w.dir)
		_ = os.RemoveAll(w.fresh)
	})
	return w
}

func TestProcessCrashCalibration(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real child processes")
	}
	w := pcrashWorldFor(t)
	for _, op := range pcrashOps {
		c := w.calibrate(t, op)
		t.Logf("%-14s seams=%d", op.name, c.seams)
	}
	seams, _ := w.calibrateMigrate(t)
	t.Logf("%-14s seams=%d", "migrate-fresh", seams)
}

// TestProcessCrashExhaustive kills every operation at every seam it has, once.
// It takes minutes, so it runs only when asked for.
func TestProcessCrashExhaustive(t *testing.T) {
	if os.Getenv("KEYORIX_PCRASH_EXHAUSTIVE") == "" {
		t.Skip("set KEYORIX_PCRASH_EXHAUSTIVE=1 to kill every operation at every seam")
	}
	w := pcrashWorldFor(t)
	for _, op := range pcrashOps {
		cal := w.calibrate(t, op)
		for killAt := int64(1); killAt <= cal.seams; killAt++ {
			t.Run(fmt.Sprintf("%s/%d", op.name, killAt), func(t *testing.T) {
				t.Parallel()
				if v := w.runPCrashExec(t, op, killAt, uint16(killAt)); len(v) > 0 {
					t.Errorf("%s", strings.Join(v, "; "))
				}
			})
		}
	}
	seams, _ := w.calibrateMigrate(t)
	for killAt := int64(1); killAt <= seams; killAt++ {
		t.Run(fmt.Sprintf("migrate-fresh/%d", killAt), func(t *testing.T) {
			t.Parallel()
			if v := w.runPCrashMigrate(t, killAt, nil); len(v) > 0 {
				t.Errorf("%s", strings.Join(v, "; "))
			}
		})
	}
}

// checkBackupAfterKilledRotation kills a DEK rotation, takes a backup with no
// restart in between, and restores that archive. A backup or restore may refuse;
// one that succeeds must give back every secret. Restarting first is not assumed
// because nothing tells an operator it is required before a backup.
//
// plant, when set, damages the restored install; only the red-proof uses it.
func (w *pcrashWorld) checkBackupAfterKilledRotation(t *testing.T, killAt int64, stateRaw uint16, plant func(target string)) []string {
	t.Helper()
	dir := t.TempDir()
	if err := pcrashCopyTree(w.dir, dir); err != nil {
		t.Fatalf("copy template: %v", err)
	}
	st, err := w.prepare(dir, stateRaw)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	run, err := pcrashOps[0].run(dir, pcrashPass, killAt)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	pcrashRecordStat("backup-after-rotate", killAt, run)
	b, err := runPCrashChild(dir, pcrashPass, "admin", []string{"backup", "--config", "./keyorix.yaml", "--output", "./post.tar.gz"}, 0)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if b.panicked() {
		return []string{"backup after a killed rotation panicked: " + pcrashTail(b.output)}
	}
	if b.exit != 0 {
		t.Logf("outcome: backup refused (killed at %s): %s", run.label, pcrashTail(b.output))
		return nil
	}
	// The restore target is the killed install itself: the key-set manifest
	// exists only once a rotation has run, and a target without it expects a
	// different key-file count and refuses for a reason unrelated to the kill.
	target := t.TempDir()
	if err := pcrashCopyTree(dir, target); err != nil {
		t.Fatalf("copy the killed install: %v", err)
	}
	r, err := runPCrashChild(target, pcrashPass, "admin", []string{"restore", "--config", "./keyorix.yaml", "--input", "./post.tar.gz", "--overwrite-existing", "--allow-rollback"}, 0)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if r.panicked() {
		return []string{"restore of the post-kill backup panicked: " + pcrashTail(r.output)}
	}
	if r.exit != 0 {
		t.Logf("outcome: restore refused (killed at %s), archive entries %v: %s", run.label, pcrashArchiveNames(filepath.Join(target, "post.tar.gz")), pcrashTail(r.output))
		return nil
	}
	if plant != nil {
		plant(target)
	}
	t.Logf("outcome: backup and restore both succeeded (killed at %s)", run.label)
	o := pcrashOpenGuarded(target, pcrashPass)
	if o.pnc != nil || o.err != nil {
		return []string{fmt.Sprintf("backup made after a kill restored successfully but the install will not open: panic=%v err=%v", o.pnc, o.err)}
	}
	defer o.inst.close()
	m, err := o.inst.observe(context.Background(), w.seed)
	if err != nil {
		return []string{"backup made after a kill restored successfully but a secret is unreadable: " + err.Error()}
	}
	if !reflect.DeepEqual(m.Ledger, st.before.Ledger) {
		return []string{fmt.Sprintf("backup made after a kill restored a different ledger: have %v, want %v", m.Ledger, st.before.Ledger)}
	}
	if plant == nil {
		return w.checkCleanHostRestore(t, dir, run.label, st)
	}
	return nil
}

const envPCrashFindings = "KEYORIX_PCRASH_FINDINGS" // set to fail on the known clean-host refusal

// checkCleanHostRestore restores the same archive onto an install that never saw
// the rotation, which is what a restore after losing the machine looks like.
//
// KNOWN FINDING: while a killed rotation's .pending key file exists, backup
// archives it (keyfiles.Registry) and exits 0, and restore then refuses the
// archive on a target without that file (validateKeyFileSetV2). Logged, not
// failed, unless envPCrashFindings is set, so the harness stays usable until
// that is decided.
func (w *pcrashWorld) checkCleanHostRestore(t *testing.T, dir, label string, st pcrashExecState) []string {
	t.Helper()
	target := t.TempDir()
	if err := pcrashCopyTree(w.dir, target); err != nil {
		t.Fatalf("copy template: %v", err)
	}
	archive, err := os.ReadFile(filepath.Join(dir, "post.tar.gz")) //nolint:gosec // test-generated path
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "post.tar.gz"), archive, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := runPCrashChild(target, pcrashPass, "admin", []string{"restore", "--config", "./keyorix.yaml", "--input", "./post.tar.gz", "--overwrite-existing", "--allow-rollback"}, 0)
	if err != nil {
		t.Fatalf("clean-host restore: %v", err)
	}
	if r.panicked() {
		return []string{"clean-host restore panicked: " + pcrashTail(r.output)}
	}
	if r.exit != 0 {
		if strings.Contains(r.output, "key file(s) but this config") {
			t.Logf("finding: clean-host restore refused (killed at %s)", label)
			if os.Getenv(envPCrashFindings) != "" {
				return []string{fmt.Sprintf("backup exited 0 but its archive is refused on a clean host (killed at %s): %s", label, pcrashTail(r.output))}
			}
			return nil
		}
		t.Logf("outcome: clean-host restore refused for another reason (killed at %s): %s", label, pcrashTail(r.output))
		return nil
	}
	t.Logf("outcome: clean-host restore succeeded (killed at %s)", label)
	o := pcrashOpenGuarded(target, pcrashPass)
	if o.pnc != nil || o.err != nil {
		return []string{fmt.Sprintf("clean-host restore succeeded but the install will not open (killed at %s): panic=%v err=%v", label, o.pnc, o.err)}
	}
	defer o.inst.close()
	m, err := o.inst.observe(context.Background(), w.seed)
	if err != nil {
		return []string{fmt.Sprintf("clean-host restore succeeded but a secret is unreadable (killed at %s): %v", label, err)}
	}
	if !reflect.DeepEqual(m.Ledger, st.before.Ledger) {
		return []string{fmt.Sprintf("clean-host restore gave a different ledger (killed at %s): have %v, want %v", label, m.Ledger, st.before.Ledger)}
	}
	return nil
}

// pcrashArchiveNames lists a gzip-compressed tar's entries, for the log only.
func pcrashArchiveNames(path string) []string {
	f, err := os.Open(path) //nolint:gosec // test-generated path
	if err != nil {
		return []string{err.Error()}
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return []string{err.Error()}
	}
	var names []string
	for tr := tar.NewReader(gz); ; {
		h, err := tr.Next()
		if err != nil {
			return names
		}
		names = append(names, h.Name)
	}
}

// TestProcessCrashBackupAfterKilledRotation runs that check at every rotation seam.
func TestProcessCrashBackupAfterKilledRotation(t *testing.T) {
	if os.Getenv("KEYORIX_PCRASH_EXHAUSTIVE") == "" {
		t.Skip("set KEYORIX_PCRASH_EXHAUSTIVE=1 to kill a rotation at every seam and back up")
	}
	w := pcrashWorldFor(t)
	cal := w.calibrate(t, pcrashOps[0])
	for killAt := int64(1); killAt <= cal.seams; killAt++ {
		t.Run(fmt.Sprintf("%d", killAt), func(t *testing.T) {
			t.Parallel()
			if v := w.checkBackupAfterKilledRotation(t, killAt, uint16(killAt), nil); len(v) > 0 {
				t.Errorf("%s", strings.Join(v, "; "))
			}
		})
	}
}

func FuzzProcessCrashRecovery(f *testing.F) {
	// One extra op index past pcrashOps is the fresh-install migration.
	// One seed each: a single execution costs seconds, and a larger corpus spent
	// a whole 90-second burst on baseline coverage without mutating anything.
	// TestProcessCrashExhaustive is what covers every kill point.
	for i := range len(pcrashOps) + 1 {
		f.Add(uint8(i), uint16(3), uint16(i)*7)
	}
	w := pcrashWorldFor(f)
	f.Fuzz(func(t *testing.T, opRaw uint8, killRaw, stateRaw uint16) {
		opIdx := int(opRaw) % (len(pcrashOps) + 1)
		if opIdx == len(pcrashOps) {
			seams, _ := w.calibrateMigrate(t)
			killAt := 1 + int64(killRaw)%(seams+1)
			if v := w.runPCrashMigrate(t, killAt, nil); len(v) > 0 {
				t.Fatalf("op=migrate-fresh killAt=%d (of %d seams): %s", killAt, seams, strings.Join(v, "; "))
			}
			return
		}
		op := pcrashOps[opIdx]
		cal := w.calibrate(t, op)
		// seams+1 is reachable only because a generated state can add rows; a
		// run past the last seam is a clean run, which must match the after model.
		killAt := 1 + int64(killRaw)%(cal.seams+1)
		if v := w.runPCrashExec(t, op, killAt, stateRaw); len(v) > 0 {
			t.Fatalf("op=%s killAt=%d state=%d (of %d seams): %s", op.name, killAt, stateRaw, cal.seams, strings.Join(v, "; "))
		}
	})
}
