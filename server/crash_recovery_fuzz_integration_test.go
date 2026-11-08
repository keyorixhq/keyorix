//go:build !windows

package main

// crash_recovery_fuzz_integration_test.go -- process-level crash-recovery fuzz.
// Rules, invariants and success criteria are pre-registered in
// CRASH_RECOVERY_FUZZ.md (same directory); read that first.
//
// Where TestEdgeCrashSoak_SQLite kills the SERVER under client writes, this
// kills the MAINTENANCE commands (DEK rotation sweep, KEK rotation, backup,
// restore) at fuzzed points, recovers the way the docs say, and checks
// whole-install invariants. It reuses the soak's server/API helpers.
//
// Env: KX_CRASH_ITERS (kill iterations per op, default 3, one per kill-point
// kind), KX_CRASH_SEED, KX_CRASH_OPS (comma list, default all; an unknown name
// fails the test), KX_CRASH_ARTIFACTS (dir; failing post-kill snapshots are
// saved here, always logged), KX_CRASH_REPLAY (snapshot dir from a previous
// failure: re-runs recovery+checks on it).

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/restorejournal"
)

const (
	crashPass2 = "crash-fuzz-passphrase-two-0002"
	crashPass3 = "crash-fuzz-passphrase-three-0003"
)

// crashRun is the crash-recovery fuzzer's view of a crashWorld: the shared
// world plus the state-A/state-B ledgers and ids only this fuzzer needs (kept
// out of fuzzharness_common_test.go, which the upgrade-path fuzzer shares).
type crashRun struct {
	*crashWorld
	projectID uint
	envID     uint
	ledgerA   crashLedger // state captured in archiveA
	ledgerB   crashLedger // state in dir
	archiveA  string
	// deletedIDs are soft-deleted before archive A, so they are in no ledger;
	// the checker still reads them and expects "<gone>".
	deletedIDs []uint
	// rotatedPass is the passphrase a rotate-kek moves the install to.
	rotatedPass string
}

func (w *crashWorld) env(pass string) []string {
	return append(baseEnv(w.dir), "KEYORIX_MASTER_PASSWORD="+pass)
}

func (l crashLedger) clone() crashLedger {
	o := crashLedger{}
	for k, v := range l {
		o[k] = append([]string(nil), v...)
	}
	return o
}

func unionIDs(ls ...crashLedger) []uint {
	seen := map[uint]bool{}
	var ids []uint
	for _, l := range ls {
		for id := range l {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	slices.Sort(ids)
	return ids
}

// buildWorld installs, populates (state A), backs up, then diverges (state B).
func buildWorld(t *testing.T, bin string, rng *rand.Rand) *crashRun {
	t.Helper()
	srv, _ := soakPrepareInstall(t, bin)
	dir := srv.dir
	w := &crashRun{crashWorld: &crashWorld{t: t, bin: bin, dir: dir, port: srv.port}, rotatedPass: crashPass2}
	srv.start("KEYORIX_BOOTSTRAP_TOKEN=" + soakBootstrapTok)
	t.Cleanup(srv.kill9) // also covers the restart below: kill9 acts on the current process
	if !srv.tryHealthy(soakHealthTimeout) {
		t.Fatalf("base install did not start:\n%s", srv.logTail())
	}
	api := newSoakAPI(srv.baseURL())
	body, _ := json.Marshal(map[string]string{"username": soakAdminUser, "email": soakAdminEmail, "password": soakAdminPassword, "display_name": soakAdminUser})
	req, _ := http.NewRequest(http.MethodPost, srv.baseURL()+"/system/init", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Keyorix-Bootstrap-Token", soakBootstrapTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap admin: err=%v\n%s", err, srv.logTail())
	}
	_ = resp.Body.Close()
	api.login(t)
	idOf := func(path string, payload map[string]string) uint {
		code, data, err := api.do(http.MethodPost, path, payload)
		var d struct {
			ID uint `json:"id"`
		}
		if err != nil || code != http.StatusCreated || json.Unmarshal(data, &d) != nil || d.ID == 0 {
			t.Fatalf("POST %s: code=%d err=%v", path, code, err)
		}
		return d.ID
	}
	w.projectID = idOf("/api/v1/projects", map[string]string{"name": "crash-project"})
	w.envID = idOf(fmt.Sprintf("/api/v1/projects/%d/environments", w.projectID), map[string]string{"name": "crash-env"})

	led := crashLedger{}
	mk := func(n int) {
		for range n {
			name := fmt.Sprintf("crash-%d-%d", len(led), rng.Intn(1e6))
			val := fmt.Sprintf("val-%s-v1-%x", name, rng.Int63())
			code, data, err := api.do(http.MethodPost, "/api/v1/secrets", map[string]any{
				"name": name, "value": val, "project_id": w.projectID, "environment_id": w.envID, "type": "generic"})
			var d struct {
				ID uint `json:"id"`
			}
			if err != nil || code != http.StatusCreated || json.Unmarshal(data, &d) != nil || d.ID == 0 {
				t.Fatalf("create secret: code=%d err=%v", code, err)
			}
			led[d.ID] = []string{val}
			for u := rng.Intn(3); u > 0; u-- {
				nv := fmt.Sprintf("val-%d-v%d-%x", d.ID, len(led[d.ID])+1, rng.Int63())
				if code, _, err := api.do(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", d.ID), map[string]any{"value": nv}); err != nil || code != http.StatusOK {
					t.Fatalf("update secret %d: code=%d err=%v", d.ID, code, err)
				}
				led[d.ID] = append(led[d.ID], nv)
			}
		}
	}
	mk(6)
	// Soft-delete two secrets before the backup: archive A must carry deleted-secret
	// rows (their versions/audit rows stay referenced), the shape that broke
	// old-release backups in the upgrade-path fuzz. Deleted ids leave the ledger
	// and are kept in deletedIDs. Ids are taken in sorted order so that one seed
	// builds one world.
	delIDs := slices.Sorted(maps.Keys(led))[:2]
	for _, id := range delIDs {
		if code, _, err := api.do(http.MethodDelete, fmt.Sprintf("/api/v1/secrets/%d", id), nil); err != nil || (code != http.StatusOK && code != http.StatusNoContent) {
			t.Fatalf("delete secret %d: code=%d err=%v", id, code, err)
		}
		delete(led, id)
	}
	w.deletedIDs = delIDs
	w.ledgerA = led.clone()
	srv.stopGraceful()
	// Archive A (server stopped: SQLite backup is exclusive).
	w.archiveA = filepath.Join(t.TempDir(), "archiveA.tar.gz")
	tmp := filepath.Join(dir, "archiveA.tar.gz")
	if out, err := runAdmin(t, bin, dir, srv.env, "backup", "--config", "./keyorix.yaml", "--output", "./archiveA.tar.gz"); err != nil {
		t.Fatalf("base backup: %v\n%s", err, out)
	}
	if err := os.Rename(tmp, w.archiveA); err != nil {
		t.Fatalf("move archive: %v", err)
	}
	// Diverge to state B: more secrets and more versions after the backup.
	srv.start()
	if !srv.tryHealthy(soakHealthTimeout) {
		t.Fatalf("base restart: %s", srv.logTail())
	}
	api = newSoakAPI(srv.baseURL())
	api.login(t)
	mk(3)
	for _, id := range slices.Sorted(maps.Keys(led)) {
		vs := led[id]
		if rng.Intn(2) == 0 {
			nv := fmt.Sprintf("val-%d-v%d-%x", id, len(vs)+1, rng.Int63())
			if code, _, err := api.do(http.MethodPut, fmt.Sprintf("/api/v1/secrets/%d", id), map[string]any{"value": nv}); err != nil || code != http.StatusOK {
				t.Fatalf("diverge update %d: %d %v", id, code, err)
			}
			led[id] = append(vs, nv)
		}
	}
	w.ledgerB = led
	srv.stopGraceful()
	return w
}

// ---- checker -------------------------------------------------------------

// ---- operations -----------------------------------------------------------

type crashOp struct {
	name string
	args func(dir string) []string
	// prep stages files the op needs inside dir.
	prep func(w *crashRun, dir string)
}

var crashOps = []crashOp{
	{name: "rotate-dek", args: func(string) []string {
		return []string{"encryption", "rotate", "--confirm", "--config", "./keyorix.yaml"}
	}},
	{name: "rotate-kek", args: func(string) []string {
		return []string{"encryption", "rotate-kek", "--confirm", "--new-passphrase-file", "./newpass", "--config", "./keyorix.yaml"}
	}, prep: func(w *crashRun, dir string) {
		_ = os.WriteFile(filepath.Join(dir, "newpass"), []byte(crashPass2), 0o600)
	}},
	{name: "backup", args: func(string) []string {
		return []string{"backup", "--config", "./keyorix.yaml", "--output", "./b.tar.gz"}
	}},
	{name: "restore", args: func(string) []string {
		return []string{"restore", "--config", "./keyorix.yaml", "--input", "./archiveA.tar.gz", "--overwrite-existing", "--allow-rollback"}
	}, prep: func(w *crashRun, dir string) {
		copyTree2(w.t, w.archiveA, filepath.Join(dir, "archiveA.tar.gz"))
	}},
}

func crashOpByName(name string) (crashOp, bool) {
	for _, o := range crashOps {
		if o.name == name {
			return o, true
		}
	}
	return crashOp{}, false
}

// allowedFor is the ledgers op may end on as a whole: a restore may be wholly
// old or wholly new, anything else must keep state B.
func (w *crashRun) allowedFor(op crashOp) []crashLedger {
	if op.name == "restore" {
		return []crashLedger{w.ledgerB, w.ledgerA}
	}
	return []crashLedger{w.ledgerB}
}

// recoverAndCheck performs documented recovery on dir and returns violations.
// allowed = ledgers the final state may equal as a whole.
func (w *crashRun) recoverAndCheck(op crashOp, dir string, allowed []crashLedger, notes *[]string) []string {
	var v []string
	ids := append(unionIDs(w.ledgerA, w.ledgerB), w.deletedIDs...)
	passes := []string{"soak-test-passphrase-edge-crash"}
	if op.name == "rotate-kek" {
		passes = []string{"soak-test-passphrase-edge-crash", w.rotatedPass}
	}
	// Journal present -> documented recovery.
	if _, err := os.Stat(filepath.Join(dir, ".keyorix-restore-journal.json")); err == nil {
		out, rerr := runAdminBounded(w.bin, dir, append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+passes[0]), "restore", "--recover", "--config", "./keyorix.yaml")
		*notes = append(*notes, fmt.Sprintf("restore-journal present -> restore --recover (err=%v): %s", rerr, tail(out, 200)))
	}
	var working []string
	var obs map[uint]string
	var lastLog string
	boot := func() {
		working, obs = nil, nil
		for _, p := range passes {
			o, up, lg := w.bootAndObserve(dir, p, ids)
			lastLog = lg
			if up {
				working = append(working, p)
				obs = o
			}
		}
	}
	boot()
	if len(working) == 0 {
		// Documented recovery #2: re-run the operation's own command (resume).
		*notes = append(*notes, "no passphrase boots -> documented resume: re-run op / restore --recover")
		for _, p := range passes {
			if op.name == "restore" {
				_, _ = runAdminBounded(w.bin, dir, append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+p), "restore", "--recover", "--config", "./keyorix.yaml")
			} else if op.name == "rotate-dek" || op.name == "rotate-kek" {
				_, _ = runAdminBounded(w.bin, dir, append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+p), op.args(dir)...)
			}
		}
		boot()
	}
	if op.name == "rotate-kek" {
		if len(working) != 1 {
			v = append(v, fmt.Sprintf("I4 rotate-kek: %d passphrases work after recovery (want exactly 1): %v", len(working), working))
		}
	} else if len(working) == 0 {
		v = append(v, "I1 server cannot start after documented recovery: "+tail(lastLog, 500))
	}
	if len(working) == 0 {
		return v
	}
	pass := working[0]
	if i, ok := matchState(obs, allowed...); !ok {
		v = append(v, fmt.Sprintf("I1/I7 observed state matches no allowed ledger (mixed/lost/half-encrypted): %v", diffObs(obs, allowed)))
	} else {
		*notes = append(*notes, fmt.Sprintf("state=allowed[%d]", i))
	}
	// Version-count ledger: the allowed ledger that matched (else B).
	vl := w.ledgerB
	if i, ok := matchState(obs, allowed...); ok {
		vl = allowed[i]
	}
	v = append(v, w.checkQuiescent(dir, pass, vl)...)
	// I5: resumable -- re-run to completion.
	switch op.name {
	case "rotate-dek":
		if out, err := runAdminBounded(w.bin, dir, append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+pass), op.args(dir)...); err != nil {
			v = append(v, fmt.Sprintf("I5 re-run rotate-dek failed: %v %s", err, tail(out, 300)))
		}
	case "rotate-kek":
		_ = os.WriteFile(filepath.Join(dir, "newpass"), []byte(crashPass3), 0o600)
		if out, err := runAdminBounded(w.bin, dir, append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+pass), op.args(dir)...); err != nil {
			v = append(v, fmt.Sprintf("I5 follow-up rotate-kek failed: %v %s", err, tail(out, 300)))
		} else {
			pass = crashPass3
		}
	}
	if op.name == "rotate-dek" || op.name == "rotate-kek" {
		o, up, lg := w.bootAndObserve(dir, pass, ids)
		if !up {
			v = append(v, "I5 server down after re-run: "+tail(lg, 300))
		} else if _, ok := matchState(o, vl); !ok {
			v = append(v, fmt.Sprintf("I5 values changed after re-run: %v", diffObs(o, []crashLedger{vl})))
		}
	}
	// I6: a (possibly partial) backup file must restore exactly to B or be refused.
	if op.name == "backup" {
		if _, err := os.Stat(filepath.Join(dir, "b.tar.gz")); err == nil {
			tgt := w.t.TempDir()
			copyTree(w.t, w.dir, tgt)
			out, rerr := runAdminBounded(w.bin, tgt, w.env(passes[0]), "restore", "--config", "./keyorix.yaml", "--input", filepath.Join(dir, "b.tar.gz"), "--overwrite-existing", "--allow-rollback")
			if rerr == nil {
				o, up, lg := w.bootAndObserve(tgt, passes[0], ids)
				if !up {
					v = append(v, "I6 restore from killed-backup file succeeded but server will not start: "+tail(lg, 300))
				} else if _, ok := matchState(o, w.ledgerB); !ok {
					v = append(v, fmt.Sprintf("I6 restore from killed-backup file succeeded with wrong data: %v", diffObs(o, []crashLedger{w.ledgerB})))
				}
			} else {
				*notes = append(*notes, "backup file present but restore refused it (ok): "+tail(out, 160))
			}
		}
	}
	return v
}

// ---- tests ------------------------------------------------------------------

func crashSeed() int64 {
	return int64(soakEnvInt("KX_CRASH_SEED", int(time.Now().UnixNano()%1_000_000)+1))
}

// parseCrashOps turns a KX_CRASH_OPS value into a set. An unknown name is an
// error: it would otherwise run nothing and pass.
func parseCrashOps(spec string) (map[string]bool, error) {
	only := map[string]bool{}
	for o := range strings.SplitSeq(spec, ",") {
		if o == "" {
			continue
		}
		if _, ok := crashOpByName(o); !ok {
			return nil, fmt.Errorf("unknown operation %q in KX_CRASH_OPS", o)
		}
		only[o] = true
	}
	return only, nil
}

// drawTimeKill picks a time-kind kill offset inside the calibrated span between
// the first and the last directory change, where the operation is mutating the
// install. Startup and key derivation come before that span, and a kill there
// tests nothing. With no observed change it falls back to the first 90%.
func drawTimeKill(rng *rand.Rand, win changeWindow, calDur time.Duration) time.Duration {
	if win.n == 0 {
		return time.Duration(rng.Int63n(int64(calDur)*9/10 + 1))
	}
	return win.first + time.Duration(rng.Int63n(int64(win.last-win.first)+1))
}

// installDigest is a SHA-256 over every regular file's relative path and
// content. It tells a kill that changed the install from one that did not.
func installDigest(t *testing.T, dir string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p) //nolint:gosec // test-generated path
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", rel, len(b))
		_, _ = h.Write(b)
		return nil
	})
	if err != nil {
		t.Fatalf("digest %s: %v", dir, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestCrashRecoveryFuzz_SQLite(t *testing.T) {
	if testing.Short() {
		t.Skip("crash-recovery fuzz spawns real processes; skipped with -short")
	}
	seed := crashSeed()
	iters := soakEnvInt("KX_CRASH_ITERS", 3)
	// The seed fixes the world and the draws, but kill points depend on calibrated
	// timing, so only a saved snapshot (KX_CRASH_REPLAY) replays a failure.
	t.Logf("crash-recovery fuzz: seed=%d iters/op=%d", seed, iters)
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // test randomness, seed logged
	only, err := parseCrashOps(os.Getenv("KX_CRASH_OPS"))
	if err != nil {
		t.Fatal(err)
	}
	artifacts := os.Getenv("KX_CRASH_ARTIFACTS")
	bin := fuzzHeadBinary(t)
	w := buildWorld(t, bin, rng)

	stats := map[string]map[string]int{}
	for _, op := range crashOps {
		if len(only) > 0 && !only[op.name] {
			continue
		}
		stats[op.name] = map[string]int{}
		// Calibration: one uninterrupted run on a copy -> runtime + change count.
		cal := t.TempDir()
		copyTree(t, w.dir, cal)
		if op.prep != nil {
			op.prep(w, cal)
		}
		var win changeWindow
		_, nChanges, calDur, calOut, calErr := runChild(w.crashWorld, cal, "soak-test-passphrase-edge-crash", op.args(cal), &killPlan{kind: "calibrate", window: &win})
		if calErr != nil {
			t.Fatalf("calibration run of %s failed: %v\n%s", op.name, calErr, calOut)
		}
		t.Logf("op %s: calibration %s, %d dir-signature changes between %s and %s", op.name, calDur.Round(time.Millisecond), nChanges, win.first.Round(time.Millisecond), win.last.Round(time.Millisecond))

		for i := range iters {
			var plan killPlan
			switch k := i % 3; k {
			case 0:
				plan = killPlan{kind: "change", n: rng.Intn(nChanges + 1)}
			case 1:
				plan = killPlan{kind: "time", after: drawTimeKill(rng, win, calDur)}
			default:
				plan = killPlan{kind: "diskfull", ulimitBl: 1 + rng.Intn(4096)}
			}
			dir := t.TempDir()
			copyTree(t, w.dir, dir)
			if op.prep != nil {
				op.prep(w, dir)
			}
			before := installDigest(t, dir)
			killed, _, _, out, cerr := runChild(w.crashWorld, dir, "soak-test-passphrase-edge-crash", op.args(dir), &plan)
			changedInstall := installDigest(t, dir) != before
			outcome := "completed"
			switch {
			case errors.Is(cerr, errChildDeadline):
				outcome = "hung"
			case killed && changedInstall:
				outcome = "killed"
			case killed:
				outcome = "killed-noeffect"
			case plan.kind == "diskfull" && cerr != nil:
				outcome = "diskfull-error"
			case cerr != nil:
				outcome = "child-error"
			}
			stats[op.name][plan.kind+"/"+outcome]++
			// Snapshot BEFORE recovery: this is the repro artifact.
			snap := t.TempDir()
			copyTree(t, dir, filepath.Join(snap, "install"))
			var notes []string
			viol := w.recoverAndCheck(op, dir, w.allowedFor(op), &notes)
			if outcome == "hung" {
				viol = append(viol, fmt.Sprintf("child did not finish: %v", cerr))
			}
			t.Logf("%s iter %d plan=%s outcome=%s notes=%v violations=%d", op.name, i, plan, outcome, notes, len(viol))
			if len(viol) > 0 {
				dest := snap
				if artifacts != "" {
					dest = filepath.Join(artifacts, fmt.Sprintf("%s-seed%d-iter%d", op.name, seed, i))
					_ = os.MkdirAll(dest, 0o700)
					copyTree(t, filepath.Join(snap, "install"), filepath.Join(dest, "install"))
					lj, _ := json.Marshal(map[string]any{"op": op.name, "plan": plan.String(), "ledgerA": w.ledgerA, "ledgerB": w.ledgerB, "deletedIDs": w.deletedIDs, "out": out, "violations": viol})
					_ = os.WriteFile(filepath.Join(dest, "meta.json"), lj, 0o600)
					_ = copyFileIfExists(w.archiveA, filepath.Join(dest, "archiveA.tar.gz"))
				}
				t.Errorf("VIOLATION %s iter %d plan=%s snapshot=%s:\n  %s", op.name, i, plan, dest, strings.Join(viol, "\n  "))
			}
		}
	}
	t.Logf("campaign stats (op -> kind/outcome -> count): %v", stats)
	// R2 counts only kills that landed and changed the install.
	effective := map[string]int{}
	for op, kinds := range stats {
		for k, n := range kinds {
			if strings.HasSuffix(k, "/killed") {
				effective[op] += n
			}
		}
	}
	t.Logf("R2 tally (kills that landed and changed the install, per op): %v", effective)
}

func copyFileIfExists(src, dst string) error {
	b, err := os.ReadFile(src) //nolint:gosec // test-generated
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}

// TestCrashRecoveryChecker_PlantedDefects (pre-registered R1): the checker must
// flag every planted defect, and pass the unmodified control. Every case goes
// through recoverAndCheck and must fail on the invariant it plants, so a case
// cannot pass on an unrelated violation.
func TestCrashRecoveryChecker_PlantedDefects(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real processes; skipped with -short")
	}
	rng := rand.New(rand.NewSource(crashSeed())) //nolint:gosec // test randomness
	bin := fuzzHeadBinary(t)
	w := buildWorld(t, bin, rng)
	pass := "soak-test-passphrase-edge-crash"
	dataOnly := crashOp{name: "planted-data-only"} // no re-run and no archive step

	fresh := func() string {
		d := t.TempDir()
		copyTree(t, w.dir, d)
		return d
	}
	execAt := func(dbPath, q string, args ...any) {
		db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer func() { _ = db.Close() }()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("plant %q: %v", q, err)
		}
	}
	exec := func(dir, q string, args ...any) { execAt(filepath.Join(dir, "keyorix.db"), q, args...) }
	// interpose is w running a wrapper in place of the server: for commands
	// whose arguments contain match it runs action, otherwise the real binary.
	// That plants a defect in a recovery command rather than in the data.
	interpose := func(match, action string) *crashRun {
		cw := *w.crashWorld
		cw.bin = fakeServerBin(t, fmt.Sprintf("case \"$*\" in\n*%q*) %s ;;\nesac\nexec %q \"$@\"", match, action, bin))
		r := *w
		r.crashWorld = &cw
		return &r
	}
	opNamed := func(name string) crashOp {
		op, ok := crashOpByName(name)
		if !ok {
			t.Fatalf("no operation %q", name)
		}
		return op
	}
	garbleDEK := func(d string) {
		if err := os.WriteFile(crashYAMLPath(t, d, "dek_path"), []byte("garbage"), 0o600); err != nil {
			t.Fatalf("garble dek: %v", err)
		}
	}
	// plantJournal leaves the journal a restore killed after staging would leave,
	// rolling forward to a database that resurrects a soft-deleted secret.
	plantJournal := func(d string) {
		const ts = "20260101-000000"
		// Recovery compares these with its own resolved paths, and a TMPDIR may
		// sit behind a symlink (/tmp on macOS).
		d, err := filepath.EvalSymlinks(d)
		if err != nil {
			t.Fatalf("resolve install dir: %v", err)
		}
		db := filepath.Join(d, "keyorix.db")
		staged := db + ".restoring-" + ts
		execAt(db, `VACUUM INTO ?`, staged) // a plain copy would miss the WAL's contents
		execAt(staged, `UPDATE secret_nodes SET deleted_at=NULL WHERE id=?`, w.deletedIDs[0])
		sum, err := restorejournal.HashFile(staged)
		if err != nil {
			t.Fatalf("hash staged db: %v", err)
		}
		if err := restorejournal.Write(filepath.Join(d, restorejournal.FileName), restorejournal.Journal{
			Version: restorejournal.Version, Backend: "sqlite", Timestamp: ts, Overwrite: true, CompletedEvent: "planted restore",
			Entries: []restorejournal.Entry{{Path: db, Staged: staged, SHA256: sum, SQLiteDB: true}},
		}); err != nil {
			t.Fatalf("write journal: %v", err)
		}
	}

	var controlNotes []string
	if v := w.recoverAndCheck(dataOnly, fresh(), w.allowedFor(dataOnly), &controlNotes); len(v) != 0 {
		t.Fatalf("CONTROL: unmodified install reports violations (checker unsound): %v", v)
	}
	someID := unionIDs(w.ledgerB)[0]
	cases := []struct {
		name string
		op   crashOp
		// plant damages dir; a non-nil result is the world to check it with.
		plant    func(d string) *crashRun
		want     string // substring of the violations
		wantNote string // substring of the recovery notes, if any
	}{
		{name: "P1-flip-ciphertext-byte", op: dataOnly, want: "I1/I7", plant: func(d string) *crashRun {
			exec(d, `UPDATE secret_versions SET encrypted_value = substr(encrypted_value,1,length(encrypted_value)-1) || char(unicode(substr(encrypted_value,length(encrypted_value),1)) % 255 + 1) WHERE secret_node_id=? AND version_number=(SELECT MAX(version_number) FROM secret_versions WHERE secret_node_id=?)`, someID, someID)
			return nil
		}},
		{name: "P2-orphan-version-row", op: dataOnly, want: "I3", plant: func(d string) *crashRun {
			exec(d, `INSERT INTO secret_versions (secret_node_id, version_number, encrypted_value, created_at) VALUES (999999, 1, x'00', CURRENT_TIMESTAMP)`)
			return nil
		}},
		{name: "P3-tamper-audit-row", op: dataOnly, want: "I2", plant: func(d string) *crashRun {
			exec(d, `UPDATE audit_events SET event_type = event_type || 'x' WHERE id = (SELECT id FROM audit_events ORDER BY id LIMIT 1 OFFSET 3)`)
			return nil
		}},
		{name: "P4-stale-dek-after-rotation", op: dataOnly, want: "I1", plant: func(d string) *crashRun {
			old := crashYAMLPath(t, d, "dek_path")
			saved, err := os.ReadFile(old) //nolint:gosec // test-generated
			if err != nil {
				t.Fatalf("read dek.key (layout changed?): %v", err)
			}
			if out, err := runAdmin(t, bin, d, w.env(pass), "encryption", "rotate", "--confirm", "--config", "./keyorix.yaml"); err != nil {
				t.Fatalf("planted-rotation: %v\n%s", err, out)
			}
			if err := os.WriteFile(old, saved, 0o600); err != nil {
				t.Fatalf("restore stale dek: %v", err)
			}
			return nil
		}},
		{name: "P5-lost-version-rows", op: dataOnly, want: "I3", plant: func(d string) *crashRun {
			exec(d, `DELETE FROM secret_versions WHERE secret_node_id=? AND version_number=1`, someID)
			return nil
		}},
		{name: "P6-resurrected-soft-deleted-secret", op: dataOnly, want: "I1/I7", plant: func(d string) *crashRun {
			exec(d, `UPDATE secret_nodes SET deleted_at=NULL WHERE id=?`, w.deletedIDs[0])
			return nil
		}},
		{name: "I4-neither-passphrase-works", op: opNamed("rotate-kek"), want: "I4 rotate-kek: 0 passphrases", plant: func(d string) *crashRun {
			garbleDEK(d)
			return nil
		}},
		// Both candidates are the same passphrase, so the install boots for both.
		{name: "I4-both-passphrases-work", op: opNamed("rotate-kek"), want: "I4 rotate-kek: 2 passphrases", plant: func(string) *crashRun {
			r := *w
			r.rotatedPass = pass
			return &r
		}},
		{name: "I5-rotate-dek-rerun-fails", op: opNamed("rotate-dek"), want: "I5 re-run rotate-dek failed", plant: func(string) *crashRun {
			return interpose("encryption rotate --confirm", "exit 7")
		}},
		{name: "I5-rotate-kek-followup-fails", op: opNamed("rotate-kek"), want: "I5 follow-up rotate-kek failed", plant: func(string) *crashRun {
			return interpose("encryption rotate-kek", "exit 7")
		}},
		{name: "I5-server-down-after-rerun", op: opNamed("rotate-dek"), want: "I5 server down after re-run", plant: func(d string) *crashRun {
			return interpose("encryption rotate --confirm", fmt.Sprintf("%q \"$@\"; printf garbage > %q; exit 0", bin, crashYAMLPath(t, d, "dek_path")))
		}},
		// Archive A presented as the killed backup: it restores cleanly to the wrong state.
		{name: "I6-archive-restores-wrong-state", op: opNamed("backup"), want: "I6 restore from killed-backup file succeeded with wrong data", plant: func(d string) *crashRun {
			copyTree2(t, w.archiveA, filepath.Join(d, "b.tar.gz"))
			return nil
		}},
		{name: "I7-journal-rolls-forward-to-mixed-state", op: opNamed("restore"), want: "I1/I7", wantNote: "restore-journal present", plant: func(d string) *crashRun {
			plantJournal(d)
			return nil
		}},
		{name: "I7-unreadable-journal-blocks-boot", op: opNamed("restore"), want: "I1 server cannot start", wantNote: "restore-journal present", plant: func(d string) *crashRun {
			if err := os.WriteFile(filepath.Join(d, restorejournal.FileName), []byte("{not json"), 0o600); err != nil {
				t.Fatalf("write journal: %v", err)
			}
			return nil
		}},
	}
	for _, c := range cases {
		d := fresh()
		rw := c.plant(d)
		if rw == nil {
			rw = w
		}
		var notes []string
		v := rw.recoverAndCheck(c.op, d, w.allowedFor(c.op), &notes)
		got := strings.Join(v, "\n")
		if !strings.Contains(got, c.want) {
			t.Errorf("planted defect %s was NOT detected as %q: checker is blind to this class; violations: %v; notes: %v", c.name, c.want, v, notes)
			continue
		}
		if c.wantNote != "" && !strings.Contains(strings.Join(notes, "\n"), c.wantNote) {
			t.Errorf("planted defect %s did not take the expected recovery path %q; notes: %v", c.name, c.wantNote, notes)
			continue
		}
		t.Logf("planted defect %s detected: %s", c.name, tail(got, 160))
	}
}

// crashYAMLPath returns the file path configured under key in dir's keyorix.yaml.
func crashYAMLPath(t *testing.T, dir, key string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml")) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	for ln := range strings.SplitSeq(string(raw), "\n") {
		ln = strings.TrimSpace(ln)
		if after, ok := strings.CutPrefix(ln, key+":"); ok {
			v := strings.Trim(strings.TrimSpace(after), `"'`)
			if !filepath.IsAbs(v) {
				v = filepath.Join(dir, v)
			}
			return v
		}
	}
	t.Fatalf("%s not found in config", key)
	return ""
}

// replayPort reads the HTTP port from a copied config: the first quoted `port:`
// line, which is the HTTP one in the install template.
func replayPort(dir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml")) //nolint:gosec // test path
	if err != nil {
		return "", fmt.Errorf("read config: %w", err)
	}
	for ln := range strings.SplitSeq(string(raw), "\n") {
		if strings.Contains(ln, "port:") && strings.Contains(ln, `"`) {
			p := strings.Trim(strings.TrimSpace(strings.SplitN(ln, ":", 2)[1]), `"`)
			if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
				return "", fmt.Errorf("config port %q is not a valid TCP port", p)
			}
			return p, nil
		}
	}
	return "", errors.New("no quoted port: line in config")
}

// TestCrashRecoveryReplay re-runs recovery + checks on a saved post-kill snapshot
// (KX_CRASH_REPLAY=<artifact dir>). Deterministic given the snapshot.
func TestCrashRecoveryReplay(t *testing.T) {
	src := os.Getenv("KX_CRASH_REPLAY")
	if src == "" {
		t.Skip("KX_CRASH_REPLAY not set")
	}
	var meta struct {
		Op         string      `json:"op"`
		LedgerA    crashLedger `json:"ledgerA"`
		LedgerB    crashLedger `json:"ledgerB"`
		DeletedIDs []uint      `json:"deletedIDs"`
	}
	b, err := os.ReadFile(filepath.Join(src, "meta.json")) //nolint:gosec // operator-supplied replay path
	if err != nil {
		t.Fatalf("meta.json: %v", err)
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatalf("meta: %v", err)
	}
	op, ok := crashOpByName(meta.Op)
	if !ok {
		t.Fatalf("meta.json names unknown operation %q", meta.Op)
	}
	bin := fuzzHeadBinary(t)
	dir := t.TempDir()
	copyTree(t, filepath.Join(src, "install"), dir)
	port, err := replayPort(dir)
	if err != nil {
		t.Fatal(err)
	}
	w := &crashRun{crashWorld: &crashWorld{t: t, bin: bin, dir: dir, port: port}, ledgerA: meta.LedgerA, ledgerB: meta.LedgerB, archiveA: filepath.Join(src, "archiveA.tar.gz"), deletedIDs: meta.DeletedIDs, rotatedPass: crashPass2}
	allowed := w.allowedFor(op)
	var notes []string
	viol := w.recoverAndCheck(op, dir, allowed, &notes)
	t.Logf("replay verdict: notes=%v violations=%v", notes, viol)
	if len(viol) > 0 {
		t.Errorf("REPLAY VIOLATION: %s", strings.Join(viol, "; "))
	}
}
