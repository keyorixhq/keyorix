package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

// L3 of the #4043 review: a failing C0 baseline is counted per SDK and shown in the report header.
func TestFailingControlsCountedAndReported(t *testing.T) {
	recs := []RunRec{
		{SDK: "go", Scen: "S03", Mut: "C0", Applied: "applied", Outcome: "ok"},
		{SDK: "java", Scen: "S03", Mut: "C0", Applied: "applied", Outcome: "died"},
		{SDK: "java", Scen: "S06", Mut: "C0", Applied: "applied", Outcome: "err:http"},
		{SDK: "java", Scen: "S06", Mut: "R05b", Applied: "applied", Outcome: "err:decode"},
	}
	bad := failingControls(recs)
	if len(bad) != 1 || bad["java"] != 2 {
		t.Fatalf("failingControls = %v, want java=2 only", bad)
	}
	if rep := report(recs, "t", time.Second); !strings.Contains(rep, "C0 CONTROLS FAILING (per SDK: java=2)") {
		t.Fatalf("report header lacks the failing controls:\n%.400s", rep)
	}
	ok := []RunRec{{SDK: "go", Mut: "C0", Applied: "applied", Outcome: "ok"}}
	if len(failingControls(ok)) != 0 || !strings.Contains(report(ok, "t", time.Second), "C0 controls: all succeeded") {
		t.Fatal("a healthy baseline must report as such")
	}
}

// L2: a token past the 20000-char cut is reported by the driver as token_seen and becomes an O4 violation.
func TestJudgeTokenSeenBeyondCut(t *testing.T) {
	sc, m := scenByID("S03"), mutByID("C0")
	if sc == nil || m == nil {
		t.Skip("S03/C0 not defined")
	}
	drv := map[string]any{"ok": false, "class": "other", "sdk_error": true, "msg": "short", "full": "short", "native": "E", "token_seen": true}
	reqs := []HReq{{Method: "GET", URI: "/x", Class: sc.Target, Mutated: true}}
	rec := judge(sc, m, drv, callInfo{}, reqs, nil)
	for _, v := range rec.Viol {
		if v.Oracle == "O4" {
			return
		}
	}
	t.Fatalf("token_seen=true produced no O4 violation: %+v", rec.Viol)
}

// L1: a connection accepted while Disarm waits is counted under the mutex, so Disarm neither panics nor misses it.
func TestDisarmWaitsForLateConnection(t *testing.T) {
	srv, err := NewHostSrv()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	for range 20 {
		srv.Arm(newSession(mutByID("C0"), "S03"))
		done := make(chan struct{})
		go func() { srv.Disarm(); close(done) }()
		if c, err := net.Dial("tcp4", srv.Addr()); err == nil { // lands while Disarm may be waking up
			_ = c.Close()
		}
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatal("Disarm did not return")
		}
	}
	if !srv.waitIdle(5 * time.Second) {
		t.Fatal("handlers still running")
	}
}
