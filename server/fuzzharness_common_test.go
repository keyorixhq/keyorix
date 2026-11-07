//go:build !windows

package main

// fuzzharness_common_test.go -- helpers shared by the crash-recovery and
// upgrade-path process-level fuzzers. This file is intentionally byte-identical
// on both branches (identical add/add merges cleanly); change both together.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
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

// crashLedger maps secret id -> versions (index 0 = v1) of plaintext values.
type crashLedger map[uint][]string

type crashWorld struct {
	t    *testing.T
	bin  string
	dir  string // quiescent base install (state B)
	port string
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
			return killed, changes, time.Since(begin), buf.String(), err
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

// fuzzHeadBinary returns the keyorix-server under test: $KX_FUZZ_HEAD_BIN when
// set (lets a cross-compiled test binary run on a host without a Go toolchain),
// otherwise the shared build of this tree.
func fuzzHeadBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("KX_FUZZ_HEAD_BIN"); p != "" {
		return p
	}
	return buildServerBinary(t)
}
