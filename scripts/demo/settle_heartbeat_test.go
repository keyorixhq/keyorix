package demo_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

// demo_settle_anomalies (lib.sh, shared by seed-demo.sh and up.sh) must never wait in silence
// (#4188): it announces the expected duration, then prints a heartbeat while it polls
// /system/info. The REAL function runs against a fake server whose uptime is "not yet" twice
// and then past the first-pass deadline; the poll/heartbeat intervals are shrunk with the
// DEMO_SETTLE_* knobs so the test takes a few seconds.

const settleToken = "fixture-token-NOT-A-REAL-TOKEN-0123456789abcdef"

func TestSettleAnomalies_HeartbeatWhileWaiting(t *testing.T) {
	for _, tool := range []string{"python3", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	var infoCalls, acks atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/system/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+settleToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		uptime := "80s" // past the 40s first pass + 20s margin
		switch infoCalls.Add(1) {
		case 1:
			uptime = "5s"
		case 2:
			uptime = "10s"
		}
		_, _ = fmt.Fprintf(w, `{"data":{"uptime":%q}}`, uptime)
	})
	mux.HandleFunc("/api/v1/audit/anomalies", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"data":{"alerts":[{"ID":7,"AlertType":"new_user","Severity":"low","AccessedBy":"admin","SecretName":"stripe-api-key"}]}}`)
	})
	mux.HandleFunc("/api/v1/audit/anomalies/7/acknowledge", func(w http.ResponseWriter, r *http.Request) {
		acks.Add(1)
		_, _ = fmt.Fprint(w, `{"data":{}}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// The server log carries the exact first-pass delay, as a native demo's does.
	logFile := filepath.Join(t.TempDir(), "server.log")
	if err := os.WriteFile(logFile, []byte("2026/11/14 02:45:36 Anomaly detection: first pass in 40s, then every 15s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lib, err := filepath.Abs("lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", `. "$LIB" && demo_settle_anomalies "$BASE" "$TOK"`) // #nosec G204 -- fixed script, test-controlled env
	cmd.Env = append(os.Environ(),
		"LIB="+lib, "BASE="+srv.URL, "TOK="+settleToken,
		"DEMO_SERVER_LOG="+logFile,
		"DEMO_SETTLE_POLL=1", "DEMO_SETTLE_HEARTBEAT=1", "DEMO_SETTLE_RETRY_SLEEP=1")
	raw, err := cmd.CombinedOutput()
	out := string(raw)
	if err != nil {
		t.Fatalf("demo_settle_anomalies failed: %v\n%s", err, out)
	}

	if !regexp.MustCompile(`settle: waiting for the anomaly detector's first pass; this takes up to \d+ minute\(s\) the first time`).MatchString(out) {
		t.Errorf("no up-front expected-duration line:\n%s", out)
	}
	if !regexp.MustCompile(`settle: still waiting, \d+s elapsed, polling /system/info`).MatchString(out) {
		t.Errorf("no heartbeat line while the server was not ready:\n%s", out)
	}
	const final = "settle: acknowledged 1 first-observation alert(s) caused by the seed itself; 0 left open"
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if got := lines[len(lines)-1]; got != final {
		t.Errorf("final line changed:\n got: %q\nwant: %q", got, final)
	}
	if acks.Load() != 1 {
		t.Errorf("acknowledged %d alerts, want 1", acks.Load())
	}
	if strings.Contains(out, settleToken) || strings.Contains(out, "Bearer") {
		t.Errorf("the output leaked the token:\n%s", out)
	}
}
