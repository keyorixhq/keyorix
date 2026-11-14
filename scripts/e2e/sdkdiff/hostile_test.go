package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func planBody(t *testing.T, p *Plan) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := p.Body(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// U13 and U14 must put JSON escapes on the wire, otherwise they never exercise escape decoding.
func TestHostileTextEscapesOnTheWire(t *testing.T) {
	for _, c := range []struct{ id, wire string }{{"U13", "\\u00e9"}, {"U14", "\\ud83d\\ude00"}} {
		m := mutByID(c.id)
		body := planBody(t, m.Plan(&Env{Cls: "V", Page: 1}))
		if !bytes.Contains(body, []byte(c.wire)) {
			t.Errorf("%s: body lacks the escape %s: %s", c.id, c.wire, body)
		}
		var doc struct {
			Data struct {
				Value string `json:"value"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("%s: %v", c.id, err)
		}
		if doc.Data.Value != m.WantMain {
			t.Errorf("%s: decodes to %q, WantMain %q", c.id, doc.Data.Value, m.WantMain)
		}
	}
}

// Every nesting body must be well-formed (N mutations test depth, not syntax) and match its declared length.
func TestHostileNestingBodiesValid(t *testing.T) {
	for _, kind := range []string{"arr", "obj", "alt"} {
		for depth := 1; depth <= 8; depth++ {
			p := nestExtra(&Env{Cls: "P", Page: 1}, kind, depth)
			body := planBody(t, p)
			if !json.Valid(body) {
				t.Errorf("%s depth %d: invalid JSON %s", kind, depth, body)
			}
			if int64(len(body)) != p.BodyLen {
				t.Errorf("%s depth %d: %d bytes, BodyLen %d", kind, depth, len(body), p.BodyLen)
			}
		}
	}
	p := mutByID("N10").Plan(&Env{Cls: "P", Page: 1})
	body := planBody(t, p)
	if int64(len(body)) != p.BodyLen {
		t.Errorf("N10: %d bytes, BodyLen %d", len(body), p.BodyLen)
	}
	// the innermost alternating level (depth 10000: an object) must carry a value
	if !bytes.Contains(body, []byte(`{"a":1}`)) {
		t.Errorf("N10: innermost object has no value: ...%s", body[len(body)-60:])
	}
}

// A client that stops reading must not keep the handler blocked past Disarm.
func TestHostSrvDisarmUnblocksStalledWriter(t *testing.T) {
	srv, err := NewHostSrv()
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	m := &Mut{ID: "TEST-BULK", Plan: func(e *Env) *Plan {
		p := validPlan(200, nil)
		p.Frame, p.BodyLen = "eof", -1
		p.Body = streamFill([]byte(`{"x":"`), []byte(`"}`), 1<<30, 'A')
		return p
	}}
	srv.Arm(newSession(m, "H"))
	c, err := net.Dial("tcp4", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck
	if _, err := c.Write([]byte("GET /health HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond) // the socket buffers fill and the handler blocks in Write
	t0 := time.Now()
	reqs := srv.Disarm()
	if d := time.Since(t0); d > 4*time.Second {
		t.Fatalf("Disarm took %s with a stalled reader", d)
	}
	if len(reqs) != 1 || !reqs[0].Mutated {
		t.Fatalf("requests %+v", reqs)
	}
	done := make(chan struct{})
	go func() { srv.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler still running after Disarm")
	}
}

func shDriver(t *testing.T, script string) *HDriver {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH")
	}
	d := &HDriver{name: "sh", argv: []string{"sh", "-c", script}, env: []string{"PATH=" + os.Getenv("PATH")}, stderr: &syncBuf{}}
	t.Cleanup(d.kill)
	return d
}

// A driver line that is not JSON is a harness record (badout), not "driver process exited" (O1).
func TestHDriverBadOutputIsNotACrash(t *testing.T) {
	d := shDriver(t, `while read l; do echo 'stray SDK print'; done`)
	drv, info := d.call("x")
	if drv != nil || info.Reason != "badout" {
		t.Fatalf("drv=%v reason=%q", drv, info.Reason)
	}
	rec := judge(scenByID("S03"), mutByID("C1"), drv, info, []HReq{{Class: "P", Mutated: true}}, nil)
	if rec.Outcome != "harness" || len(rec.Viol) != 0 {
		t.Fatalf("outcome %s viol %+v", rec.Outcome, rec.Viol)
	}
}

func fdCount(t *testing.T) int {
	t.Helper()
	es, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skip("no /dev/fd")
	}
	return len(es)
}

// The unknown-triple return of hostile replay releases the mock server and the driver.
func TestHostileReplayReleasesOnError(t *testing.T) {
	dir := t.TempDir()
	before := fdCount(t)
	err := hostileReplay([]string{"-sdks-dir", dir, "-build", dir, "-root", dir, "-triples", "go:S99:C0", "-n", "1"})
	if err == nil || !strings.Contains(err.Error(), "unknown triple") {
		t.Fatalf("err %v", err)
	}
	if after := fdCount(t); after > before {
		t.Fatalf("%d file descriptors before, %d after", before, after)
	}
}

// S13m echoes the Authorization header in the server body: reflection is the informational O4r, never O4.
func TestJudgeS13mReflectionIsO4r(t *testing.T) {
	drv := map[string]any{"ok": false, "class": "http", "native": "APIError", "sdk_error": true,
		"msg": "500: Bearer " + canary, "full": "APIError: 500: Bearer " + canary}
	reqs := []HReq{{Class: "P", Mutated: true}}
	rec := judge(scenByID("S03"), mutByID("S13m"), drv, callInfo{Stderr: "log " + canary}, reqs, nil)
	for _, v := range rec.Viol {
		if v.Oracle == "O4" {
			t.Fatalf("S13m raised O4: %+v", v)
		}
	}
	if len(rec.Notes) == 0 || !strings.HasPrefix(rec.Notes[0], "O4r") {
		t.Fatalf("notes %v", rec.Notes)
	}
	// the same output for another mutation is a HIGH O4
	rec = judge(scenByID("S03"), mutByID("S01m"), drv, callInfo{}, reqs, nil)
	if len(rec.Viol) == 0 || rec.Viol[0].Oracle != "O4" || rec.Viol[0].Sev != "HIGH" {
		t.Fatalf("S01m viol %+v", rec.Viol)
	}
}

const nodeStubSDK = `'use strict';
class KeyorixError extends Error {}
class AuthError extends KeyorixError {}
class SecretNotFoundError extends KeyorixError {}
let n = 0;
class Client {
  constructor(base, token, opts) {}
  async health() {
    n++;
    if (n === 1) { setTimeout(() => { Promise.reject(new Error('late-from-call-1')); }, 100); return 'first'; }
    if (n === 2) { await new Promise((r) => setTimeout(r, 400)); return 'second'; }
    if (n === 3) { setTimeout(() => { throw new Error('thrown-in-call-3'); }, 10); return new Promise(() => {}); }
    return 'later';
  }
}
for (const m of ['listSecretsScoped', 'getSecretScoped', 'getSecretIn', 'getSecretByRef', 'listDeletedSecrets', 'listProjects', 'createProject', 'listEnvironments']) Client.prototype[m] = async function () { return []; };
module.exports = { Client, KeyorixError, AuthError, SecretNotFoundError, login: async () => 'tok' };
`

func nodeDriver(t *testing.T, hostile bool) *HDriver {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not on PATH")
	}
	sdks := t.TempDir()
	if err := os.MkdirAll(filepath.Join(sdks, "node"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sdks, "node", "keyorix.js"), []byte(nodeStubSDK), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := hostileDriver("node", ".", "", sdks)
	if err != nil {
		t.Fatal(err)
	}
	if !hostile {
		d.env = []string{"PATH=" + os.Getenv("PATH"), "SDKDIFF_SDKS_DIR=" + sdks}
	}
	t.Cleanup(d.kill)
	return d
}

func healthLine(timeoutMs string) string {
	return strings.Join([]string{"health", hexs("http://127.0.0.1:1"), hexs("t"), timeoutMs}, "\t")
}

// A late rejection of call 1 that fires during call 2 is not attributed to call 2 and does not replace its result;
// a call that never settles after a side event is answered as abandoned and the harness restarts the driver.
func TestNodeDriverSideEventAttribution(t *testing.T) {
	d := nodeDriver(t, true)
	r1, _ := d.call(healthLine("200"))
	if r1["ok"] != true || r1["side_events"] != nil {
		t.Fatalf("call 1: %v", r1)
	}
	r2, _ := d.call(healthLine("200"))
	if r2["ok"] != true || r2["value"] != "second" || r2["side_events"] != nil {
		t.Fatalf("call 2 took call 1's late rejection: %v", r2)
	}
	if ev, _ := r2["late_side_events"].([]any); len(ev) != 1 || !strings.Contains(str(ev[0]), "call 1 (answered)") {
		t.Fatalf("call 2 late_side_events: %v", r2["late_side_events"])
	}
	r3, _ := d.call(healthLine("200"))
	if r3["abandoned"] != true || r3["native"] != "SideEvent" {
		t.Fatalf("call 3: %v", r3)
	}
	if ev, _ := r3["side_events"].([]any); len(ev) != 1 || !strings.Contains(str(ev[0]), "thrown-in-call-3") {
		t.Fatalf("call 3 side_events: %v", r3["side_events"])
	}
	if d.cmd != nil {
		t.Fatal("driver not restarted after an abandoned call")
	}
	// the restarted driver has a fresh SDK module: its first call is clean again
	if r4, _ := d.call(healthLine("200")); r4["ok"] != true || r4["value"] != "first" {
		t.Fatalf("call 4: %v", r4)
	}
}

// Outside hostile mode the driver installs no handlers: call 1's late unhandled rejection ends the process during
// call 2, as Node does by default.
func TestNodeDriverHandlersOnlyInHostileMode(t *testing.T) {
	d := nodeDriver(t, false)
	if r, _ := d.call(healthLine("200")); r["ok"] != true {
		t.Fatalf("call 1: %v", r)
	}
	if r, info := d.call(healthLine("200")); r != nil || info.Reason != "died" {
		t.Fatalf("call 2 in differential mode: %v %+v", r, info)
	}
}
