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
// Env: KX_CRASH_ITERS (kill iterations per op, default 2), KX_CRASH_SEED,
// KX_CRASH_OPS (comma list, default all), KX_CRASH_ARTIFACTS (dir; failing
// post-kill snapshots are saved here, always logged), KX_CRASH_REPLAY
// (snapshot dir from a previous failure: re-runs recovery+checks on it).

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	crashPass1 = "crash-fuzz-passphrase-one-0001"
	crashPass2 = "crash-fuzz-passphrase-two-0002"
	crashPass3 = "crash-fuzz-passphrase-three-0003"
)

// crashLedger maps secret id -> versions (index 0 = v1) of plaintext values.
type crashLedger map[uint][]string

func (l crashLedger) clone() crashLedger {
	o := crashLedger{}
	for k, v := range l {
		o[k] = append([]string(nil), v...)
	}
	return o
}

type crashWorld struct {
	t         *testing.T
	bin       string
	dir       string // quiescent base install (state B)
	port      string
	projectID uint
	envID     uint
	ledgerA   crashLedger // state captured in archiveA
	ledgerB   crashLedger // state in dir
	archiveA  string
}

func (w *crashWorld) env(pass string) []string {
	return append(baseEnv(w.dir), "KEYORIX_MASTER_PASSWORD="+pass)
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm()|0o700)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		in, err := os.Open(p) //nolint:gosec // test-generated path
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm()) //nolint:gosec // test-generated path
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = out.Close()
			return err
		}
		return out.Close()
	})
	if err != nil {
		t.Fatalf("copyTree %s -> %s: %v", src, dst, err)
	}
}

// stopGraceful SIGTERMs the server and waits (SIGKILL fallback).
func (s *soakServer) stopGraceful() {
	if s.cmd == nil {
		return
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.exited:
		s.cmd = nil
	case <-time.After(8 * time.Second):
		s.kill9()
	}
}

// tryHealthy is waitHealthy without t.Fatalf: false means "did not come up".
func (s *soakServer) tryHealthy(timeout time.Duration) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	begin := time.Now()
	for time.Since(begin) < timeout {
		select {
		case <-s.exited:
			return false
		default:
		}
		if resp, err := client.Get(s.baseURL() + "/health"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func (w *crashWorld) server(dir, pass string) *soakServer {
	return &soakServer{t: w.t, bin: w.bin, dir: dir, env: append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+pass),
		port: w.port, logPath: filepath.Join(dir, "crash-server.log")}
}

// buildWorld installs, populates (state A), backs up, then diverges (state B).
func buildWorld(t *testing.T, bin string, rng *rand.Rand) *crashWorld {
	t.Helper()
	// soakPrepareInstall uses its own fixed passphrase; override via env below.
	srv, _ := soakPrepareInstall(t, bin)
	dir := srv.dir
	// Re-key to our passphrases is not needed: keep the soak passphrase as pass1.
	for i, e := range srv.env {
		if strings.HasPrefix(e, "KEYORIX_MASTER_PASSWORD=") {
			srv.env[i] = "KEYORIX_MASTER_PASSWORD=soak-test-passphrase-edge-crash"
		}
	}
	w := &crashWorld{t: t, bin: bin, dir: dir, port: srv.port}
	srv.start("KEYORIX_BOOTSTRAP_TOKEN=" + soakBootstrapTok)
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
		for i := 0; i < n; i++ {
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
	for id, vs := range led {
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

// observe reads every secret in ids via the API of a server on dir.
func observe(api *soakAPI, ids []uint) map[uint]string {
	o := map[uint]string{}
	for _, id := range ids {
		code, data, err := api.do(http.MethodGet, fmt.Sprintf("/api/v1/secrets/%d?include_value=true", id), nil)
		switch {
		case err != nil:
			o[id] = "<transport-error>"
		case code == http.StatusNotFound || code == http.StatusGone:
			o[id] = "<gone>"
		case code != http.StatusOK:
			o[id] = fmt.Sprintf("<status-%d>", code)
		default:
			var d struct {
				Value string `json:"value"`
			}
			_ = json.Unmarshal(data, &d)
			o[id] = d.Value
		}
	}
	return o
}

func latest(l crashLedger, id uint) string {
	if vs, ok := l[id]; ok {
		return vs[len(vs)-1]
	}
	return "<gone>"
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
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// matchState reports which allowed ledgers the observation equals entirely.
func matchState(obs map[uint]string, allowed ...crashLedger) (idx int, ok bool) {
	for i, l := range allowed {
		all := true
		for id, v := range obs {
			if latest(l, id) != v {
				all = false
				break
			}
		}
		if all {
			return i, true
		}
	}
	return -1, false
}

// checkQuiescent runs the SQL + CLI invariants on a stopped install.
// versionLedger is the ledger whose version counts must match.
func (w *crashWorld) checkQuiescent(dir, pass string, versionLedger crashLedger) []string {
	var v []string
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+pass)
	if out, err := runAdmin(w.t, w.bin, dir, env, "verify-audit", "--config", "./keyorix.yaml"); err != nil || !strings.Contains(out, "VALID") {
		v = append(v, fmt.Sprintf("I2 verify-audit not VALID (err=%v): %s", err, tail(out, 400)))
	}
	if out, err := runAdmin(w.t, w.bin, dir, env, "encryption", "validate", "--config", "./keyorix.yaml"); err != nil {
		v = append(v, fmt.Sprintf("I4 encryption validate failed: %v %s", err, tail(out, 400)))
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "keyorix.db")+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return append(v, "I3 open db: "+err.Error())
	}
	defer func() { _ = db.Close() }()
	var ic string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&ic); err != nil || ic != "ok" {
		v = append(v, fmt.Sprintf("I3 integrity_check=%q err=%v", ic, err))
	}
	var orphans int
	if err := db.QueryRow(`SELECT COUNT(*) FROM secret_versions v LEFT JOIN secret_nodes n ON n.id=v.secret_node_id WHERE n.id IS NULL`).Scan(&orphans); err != nil {
		v = append(v, "I3 orphan query: "+err.Error())
	} else if orphans > 0 {
		v = append(v, fmt.Sprintf("I3 %d orphaned secret_versions rows", orphans))
	}
	for id, vs := range versionLedger {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM secret_versions WHERE secret_node_id=?`, id).Scan(&n); err != nil {
			v = append(v, fmt.Sprintf("I3 version count %d: %v", id, err))
		} else if n != len(vs) {
			v = append(v, fmt.Sprintf("I3 secret %d has %d version rows, ledger says %d", id, n, len(vs)))
		}
	}
	return v
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// bootAndObserve starts a server on dir with pass and observes all ids.
func (w *crashWorld) bootAndObserve(dir, pass string, ids []uint) (obs map[uint]string, up bool, logTail string) {
	srv := w.server(dir, pass)
	srv.start()
	defer srv.stopGraceful()
	if !srv.tryHealthy(soakHealthTimeout) {
		return nil, false, srv.logTail()
	}
	api := newSoakAPI(srv.baseURL())
	code, _, err := api.do(http.MethodPost, "/auth/login", map[string]string{"username": soakAdminUser, "password": soakAdminPassword})
	if err != nil || code != http.StatusOK {
		return nil, false, fmt.Sprintf("login failed code=%d err=%v", code, err)
	}
	api.login(w.t)
	return observe(api, ids), true, ""
}

// ---- operations -----------------------------------------------------------

type crashOp struct {
	name string
	args func(dir string) []string
	// prep stages files the op needs inside dir.
	prep func(w *crashWorld, dir string)
}

var crashOps = []crashOp{
	{name: "rotate-dek", args: func(string) []string {
		return []string{"encryption", "rotate", "--confirm", "--config", "./keyorix.yaml"}
	}},
	{name: "rotate-kek", args: func(string) []string {
		return []string{"encryption", "rotate-kek", "--confirm", "--new-passphrase-file", "./newpass", "--config", "./keyorix.yaml"}
	}, prep: func(w *crashWorld, dir string) {
		_ = os.WriteFile(filepath.Join(dir, "newpass"), []byte(crashPass2), 0o600)
	}},
	{name: "backup", args: func(string) []string {
		return []string{"backup", "--config", "./keyorix.yaml", "--output", "./b.tar.gz"}
	}},
	{name: "restore", args: func(string) []string {
		return []string{"restore", "--config", "./keyorix.yaml", "--input", "./archiveA.tar.gz", "--overwrite-existing", "--allow-rollback"}
	}, prep: func(w *crashWorld, dir string) {
		copyTree2(w.t, w.archiveA, filepath.Join(dir, "archiveA.tar.gz"))
	}},
}

func copyTree2(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src) //nolint:gosec // test-generated
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

// dirSig is a cheap signature of the install directory: names + sizes.
func dirSig(dir string) string {
	var parts []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, e := d.Info(); e == nil {
			rel, _ := filepath.Rel(dir, p)
			parts = append(parts, fmt.Sprintf("%s:%d", rel, info.Size()))
		}
		return nil
	})
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

type killPlan struct {
	kind     string // "change", "time", "diskfull"
	n        int    // change index
	after    time.Duration
	ulimitBl int // diskfull: ulimit -f blocks
}

func (p killPlan) String() string {
	return fmt.Sprintf("%s(n=%d after=%s ulimit=%d)", p.kind, p.n, p.after, p.ulimitBl)
}

// runChild runs `<bin> admin <args>` in dir under plan. changes is the number of
// dir-signature changes observed (for calibration). killed is true if the plan's
// SIGKILL landed before the child exited by itself.
func runChild(w *crashWorld, dir, pass string, args []string, plan *killPlan) (killed bool, changes int, dur time.Duration, out string, exitErr error) {
	var cmd *exec.Cmd
	full := append([]string{"admin"}, args...)
	if plan != nil && plan.kind == "diskfull" {
		cmd = exec.Command("/bin/sh", append([]string{"-c", `ulimit -f "$1"; shift; exec "$@"`, "sh", fmt.Sprint(plan.ulimitBl), w.bin}, full...)...) //nolint:gosec // test-controlled args
	} else {
		cmd = exec.Command(w.bin, full...) //nolint:gosec // test-controlled args
	}
	cmd.Dir = dir
	cmd.Env = append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+pass)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	begin := time.Now()
	if err := cmd.Start(); err != nil {
		w.t.Fatalf("start child: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	last := dirSig(dir)
	for {
		select {
		case err := <-done:
			return false, changes, time.Since(begin), buf.String(), err
		default:
		}
		if plan != nil && !killed {
			doKill := false
			switch plan.kind {
			case "change":
				doKill = changes >= plan.n
			case "time":
				doKill = time.Since(begin) >= plan.after
			}
			if doKill {
				_ = cmd.Process.Signal(syscall.SIGKILL)
				killed = true
			}
		}
		if s := dirSig(dir); s != last {
			last = s
			changes++
		}
		time.Sleep(300 * time.Microsecond)
	}
}

// recoverAndCheck performs documented recovery on dir and returns violations.
// allowed = ledgers the final state may equal as a whole.
func (w *crashWorld) recoverAndCheck(op crashOp, dir string, allowed []crashLedger, notes *[]string) []string {
	var v []string
	ids := unionIDs(w.ledgerA, w.ledgerB)
	passes := []string{"soak-test-passphrase-edge-crash"}
	if op.name == "rotate-kek" {
		passes = []string{"soak-test-passphrase-edge-crash", crashPass2}
	}
	// Journal present -> documented recovery.
	if _, err := os.Stat(filepath.Join(dir, ".keyorix-restore-journal.json")); err == nil {
		out, rerr := runAdmin(w.t, w.bin, dir, append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+passes[0]), "restore", "--recover", "--config", "./keyorix.yaml")
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
				_, _ = runAdmin(w.t, w.bin, dir, append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+p), "restore", "--recover", "--config", "./keyorix.yaml")
			} else if op.name == "rotate-dek" || op.name == "rotate-kek" {
				_, _ = runAdmin(w.t, w.bin, dir, append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+p), op.args(dir)...)
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
		if out, err := runAdmin(w.t, w.bin, dir, append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+pass), op.args(dir)...); err != nil {
			v = append(v, fmt.Sprintf("I5 re-run rotate-dek failed: %v %s", err, tail(out, 300)))
		}
	case "rotate-kek":
		_ = os.WriteFile(filepath.Join(dir, "newpass"), []byte(crashPass3), 0o600)
		if out, err := runAdmin(w.t, w.bin, dir, append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD="+pass), op.args(dir)...); err != nil {
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
			out, rerr := runAdmin(w.t, w.bin, tgt, w.env(passes[0]), "restore", "--config", "./keyorix.yaml", "--input", filepath.Join(dir, "b.tar.gz"), "--overwrite-existing", "--allow-rollback")
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

func diffObs(obs map[uint]string, allowed []crashLedger) string {
	var b strings.Builder
	for id, o := range obs {
		want := make([]string, len(allowed))
		okAny := false
		for i, l := range allowed {
			want[i] = latest(l, id)
			if want[i] == o {
				okAny = true
			}
		}
		if !okAny {
			fmt.Fprintf(&b, "[id %d got %.40q want %.40q] ", id, o, want)
		}
	}
	return b.String()
}

// ---- tests ------------------------------------------------------------------

func crashSeed() int64 {
	return int64(soakEnvInt("KX_CRASH_SEED", int(time.Now().UnixNano()%1_000_000)+1))
}

func TestCrashRecoveryFuzz_SQLite(t *testing.T) {
	if testing.Short() {
		t.Skip("crash-recovery fuzz spawns real processes; skipped with -short")
	}
	seed := crashSeed()
	iters := soakEnvInt("KX_CRASH_ITERS", 2)
	t.Logf("crash-recovery fuzz: seed=%d iters/op=%d (replay with KX_CRASH_SEED=%d)", seed, iters, seed)
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // test randomness, seed logged
	only := map[string]bool{}
	for _, o := range strings.Split(os.Getenv("KX_CRASH_OPS"), ",") {
		if o != "" {
			only[o] = true
		}
	}
	artifacts := os.Getenv("KX_CRASH_ARTIFACTS")
	bin := buildServerBinary(t)
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
		_, nChanges, calDur, calOut, calErr := runChild(w, cal, "soak-test-passphrase-edge-crash", op.args(cal), nil)
		if calErr != nil {
			t.Fatalf("calibration run of %s failed: %v\n%s", op.name, calErr, calOut)
		}
		t.Logf("op %s: calibration %s, %d dir-signature changes", op.name, calDur.Round(time.Millisecond), nChanges)

		for i := 0; i < iters; i++ {
			var plan killPlan
			switch k := i % 3; k {
			case 0:
				plan = killPlan{kind: "change", n: rng.Intn(nChanges + 1)}
			case 1:
				plan = killPlan{kind: "time", after: time.Duration(rng.Int63n(int64(calDur) + 1))}
			default:
				plan = killPlan{kind: "diskfull", ulimitBl: 1 + rng.Intn(4096)}
			}
			dir := t.TempDir()
			copyTree(t, w.dir, dir)
			if op.prep != nil {
				op.prep(w, dir)
			}
			killed, _, _, out, cerr := runChild(w, dir, "soak-test-passphrase-edge-crash", op.args(dir), &plan)
			outcome := "completed"
			switch {
			case killed:
				outcome = "killed"
			case plan.kind == "diskfull" && cerr != nil:
				outcome = "diskfull-error"
			case cerr != nil:
				outcome = "child-error"
			}
			stats[op.name][plan.kind+"/"+outcome]++
			// Snapshot BEFORE recovery: this is the repro artifact.
			snap := t.TempDir()
			copyTree(t, dir, filepath.Join(snap, "install"))
			allowed := []crashLedger{w.ledgerB}
			if op.name == "restore" {
				allowed = []crashLedger{w.ledgerB, w.ledgerA}
			}
			var notes []string
			viol := w.recoverAndCheck(op, dir, allowed, &notes)
			t.Logf("%s iter %d plan=%s outcome=%s notes=%v violations=%d", op.name, i, plan, outcome, notes, len(viol))
			if len(viol) > 0 {
				dest := snap
				if artifacts != "" {
					dest = filepath.Join(artifacts, fmt.Sprintf("%s-seed%d-iter%d", op.name, seed, i))
					_ = os.MkdirAll(dest, 0o700)
					copyTree(t, filepath.Join(snap, "install"), filepath.Join(dest, "install"))
					lj, _ := json.Marshal(map[string]any{"op": op.name, "plan": plan.String(), "ledgerA": w.ledgerA, "ledgerB": w.ledgerB, "out": out, "violations": viol})
					_ = os.WriteFile(filepath.Join(dest, "meta.json"), lj, 0o600)
					_ = copyFileIfExists(w.archiveA, filepath.Join(dest, "archiveA.tar.gz"))
				}
				t.Errorf("VIOLATION %s iter %d plan=%s snapshot=%s:\n  %s", op.name, i, plan, dest, strings.Join(viol, "\n  "))
			}
		}
	}
	t.Logf("campaign stats (op -> kind/outcome -> count): %v", stats)
}

func copyFileIfExists(src, dst string) error {
	b, err := os.ReadFile(src) //nolint:gosec // test-generated
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}

// TestCrashRecoveryChecker_PlantedDefects (pre-registered R1): the checker must
// flag every planted defect, and pass the unmodified control.
func TestCrashRecoveryChecker_PlantedDefects(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns real processes; skipped with -short")
	}
	rng := rand.New(rand.NewSource(crashSeed())) //nolint:gosec // test randomness
	bin := buildServerBinary(t)
	w := buildWorld(t, bin, rng)
	ids := unionIDs(w.ledgerB)
	pass := "soak-test-passphrase-edge-crash"

	full := func(dir string) []string {
		var v []string
		o, up, lg := w.bootAndObserve(dir, pass, ids)
		if !up {
			return []string{"server down: " + tail(lg, 200)}
		}
		if _, ok := matchState(o, w.ledgerB); !ok {
			v = append(v, "observed state mismatch: "+diffObs(o, []crashLedger{w.ledgerB}))
		}
		return append(v, w.checkQuiescent(dir, pass, w.ledgerB)...)
	}
	fresh := func() string {
		d := t.TempDir()
		copyTree(t, w.dir, d)
		return d
	}
	exec := func(dir, q string, args ...any) {
		db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "keyorix.db")+"?_pragma=busy_timeout(5000)")
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer func() { _ = db.Close() }()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("plant %q: %v", q, err)
		}
	}

	if v := full(fresh()); len(v) != 0 {
		t.Fatalf("CONTROL: unmodified install reports violations (checker unsound): %v", v)
	}
	someID := ids[0]
	cases := []struct {
		name  string
		plant func(dir string)
	}{
		{"P1-flip-ciphertext-byte", func(d string) {
			exec(d, `UPDATE secret_versions SET encrypted_value = substr(encrypted_value,1,length(encrypted_value)-1) || char(unicode(substr(encrypted_value,length(encrypted_value),1)) % 255 + 1) WHERE secret_node_id=? AND version_number=(SELECT MAX(version_number) FROM secret_versions WHERE secret_node_id=?)`, someID, someID)
		}},
		{"P2-orphan-version-row", func(d string) {
			exec(d, `INSERT INTO secret_versions (secret_node_id, version_number, encrypted_value, created_at) VALUES (999999, 1, x'00', CURRENT_TIMESTAMP)`)
		}},
		{"P3-tamper-audit-row", func(d string) {
			exec(d, `UPDATE audit_events SET event_type = event_type || 'x' WHERE id = (SELECT id FROM audit_events ORDER BY id LIMIT 1 OFFSET 3)`)
		}},
		{"P4-stale-dek-after-rotation", func(d string) {
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
		}},
		{"P5-lost-version-rows", func(d string) {
			exec(d, `DELETE FROM secret_versions WHERE secret_node_id=? AND version_number=1`, someID)
		}},
	}
	for _, c := range cases {
		d := fresh()
		c.plant(d)
		if v := full(d); len(v) == 0 {
			t.Errorf("planted defect %s was NOT detected: checker is blind to this class", c.name)
		} else {
			t.Logf("planted defect %s detected: %s", c.name, tail(v[0], 160))
		}
	}
}

// crashYAMLPath returns the file path configured under key in dir's keyorix.yaml.
func crashYAMLPath(t *testing.T, dir, key string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml")) //nolint:gosec // test path
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	for _, ln := range strings.Split(string(raw), "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, key+":") {
			v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(ln, key+":")), `"'`)
			if !filepath.IsAbs(v) {
				v = filepath.Join(dir, v)
			}
			return v
		}
	}
	t.Fatalf("%s not found in config", key)
	return ""
}

// TestCrashRecoveryReplay re-runs recovery + checks on a saved post-kill snapshot
// (KX_CRASH_REPLAY=<artifact dir>). Deterministic given the snapshot.
func TestCrashRecoveryReplay(t *testing.T) {
	src := os.Getenv("KX_CRASH_REPLAY")
	if src == "" {
		t.Skip("KX_CRASH_REPLAY not set")
	}
	var meta struct {
		Op      string      `json:"op"`
		LedgerA crashLedger `json:"ledgerA"`
		LedgerB crashLedger `json:"ledgerB"`
	}
	b, err := os.ReadFile(filepath.Join(src, "meta.json")) //nolint:gosec // operator-supplied replay path
	if err != nil {
		t.Fatalf("meta.json: %v", err)
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatalf("meta: %v", err)
	}
	bin := buildServerBinary(t)
	dir := t.TempDir()
	copyTree(t, filepath.Join(src, "install"), dir)
	w := &crashWorld{t: t, bin: bin, dir: dir, ledgerA: meta.LedgerA, ledgerB: meta.LedgerB, archiveA: filepath.Join(src, "archiveA.tar.gz")}
	// Port from the copied config.
	if raw, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml")); err == nil { //nolint:gosec // test path
		for _, ln := range strings.Split(string(raw), "\n") {
			if strings.Contains(ln, "port:") && strings.Contains(ln, `"`) {
				w.port = strings.Trim(strings.TrimSpace(strings.SplitN(ln, ":", 2)[1]), `"`)
				break
			}
		}
	}
	var op crashOp
	for _, o := range crashOps {
		if o.name == meta.Op {
			op = o
		}
	}
	allowed := []crashLedger{w.ledgerB}
	if op.name == "restore" {
		allowed = []crashLedger{w.ledgerB, w.ledgerA}
	}
	var notes []string
	viol := w.recoverAndCheck(op, dir, allowed, &notes)
	t.Logf("replay verdict: notes=%v violations=%v", notes, viol)
	if len(viol) > 0 {
		t.Errorf("REPLAY VIOLATION: %s", strings.Join(viol, "; "))
	}
}
