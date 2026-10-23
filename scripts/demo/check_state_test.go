package demo_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// These tests pin DEMO-WALK-4 findings 8 and 9: check.sh --url must find the native demo's
// .demo-native/state.env (it used to read only .demo-2-state, so every authenticated step
// failed with 401), and on a USED demo (--used) new_user/new_ip alerts are a WARN while a
// fresh demo stays strict. The real check.sh runs against a fake API server; only the steps
// named in KEYORIX_CHECK_ONLY run (the full walk needs a real server).

type fakeAPI struct {
	mu        sync.Mutex
	alerts    []map[string]any // returned by /api/v1/audit/anomalies
	gaps      []string         // control ids reported as "gap"
	loginUser string
	loginPass string
	machine   string // bearer token seen on the by-ref read
}

// The handler goroutines run while the test body is still setting up and asserting, so every
// access from the test goes through these (the -race CI leg caught the unlocked version).
func (f *fakeAPI) setAlerts(a ...map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alerts = a
}

func (f *fakeAPI) setGaps(g ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gaps = g
}

func (f *fakeAPI) seen() (loginPass, machine string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loginPass, f.machine
}

func (f *fakeAPI) handler() http.Handler {
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": v})
	}
	mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Username, Password string }
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		f.loginUser, f.loginPass = b.Username, b.Password
		f.mu.Unlock()
		if b.Password != "native-admin-pw" {
			http.Error(w, `{"error":"bad credentials"}`, http.StatusUnauthorized)
			return
		}
		reply(w, map[string]any{"mfa_required": true, "mfa_challenge": "chal"})
	})
	mux.HandleFunc("/auth/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"token": "admin-session"})
	})
	mux.HandleFunc("/api/v1/secrets/value", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.mu.Lock()
		f.machine = tok
		f.mu.Unlock()
		if tok != "kx_machine_native" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}
		reply(w, map[string]any{"value": "v", "secret": map[string]any{"id": 1}})
	})
	mux.HandleFunc("/api/v1/system/info", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"uptime": "2h0m0s"})
	})
	mux.HandleFunc("/api/v1/audit/anomalies", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		reply(w, map[string]any{"alerts": f.alerts})
	})
	mux.HandleFunc("/api/v1/compliance/controls", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		controls := []map[string]any{
			{"id": "secret-rotation", "status": "pass", "detail": "x; 12 of 13 secrets covered"},
			{"id": "anomaly-detection", "status": "pass", "detail": ""},
		}
		for _, g := range f.gaps {
			for _, c := range controls {
				if c["id"] == g {
					c["status"] = "gap"
				}
			}
		}
		reply(w, map[string]any{"controls": controls})
	})
	return mux
}

func alert(id int, typ, sev, who string) map[string]any {
	return map[string]any{"ID": id, "AlertType": typ, "Severity": sev, "AccessedBy": who, "SecretName": "stripe-api-key"}
}

type checkEnv struct {
	root string
	url  string
	api  *fakeAPI
}

func newCheckEnv(t *testing.T) *checkEnv {
	t.Helper()
	api := &fakeAPI{gaps: []string{"secret-rotation"}}
	srv := httptest.NewServer(api.handler())
	t.Cleanup(srv.Close)
	root := t.TempDir()
	for _, f := range []string{"check.sh", "lib.sh"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(root, "scripts", "demo", f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, raw, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// check.sh builds the TOTP helper only when missing; a shim makes that a no-op.
	shim := filepath.Join(root, "bin", "totpgen")
	if err := os.MkdirAll(filepath.Dir(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shim, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &checkEnv{root: root, url: srv.URL, api: api}
}

// writeNativeState writes what native-up.sh / seed-demo.sh write (scripts/demo/seed-demo.sh).
func (e *checkEnv) writeNativeState(t *testing.T, path, url string) {
	t.Helper()
	body := "DEMO_URL='" + url + "'\n" +
		"DEMO_ADMIN_PASSWORD='native-admin-pw'\nDEMO_ADMIN_TOTP='JBSWY3DPEHPK3PXP'\n" +
		"DEMO_ALICE_PASSWORD='alice-pw'\nDEMO_ALICE_TOTP='JBSWY3DPEHPK3PXP'\n" +
		"DEMO_MACHINE_TOKEN='kx_machine_native'\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *checkEnv) run(t *testing.T, only string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join(e.root, "scripts", "demo", "check.sh"), "--no-ui"}, args...)...)
	cmd.Dir = e.root
	cmd.Env = append(os.Environ(), "KEYORIX_CHECK_ONLY="+only, "DEMO_STEP_DIR="+filepath.Join(e.root, "step"))
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func TestCheck_UrlFindsNativeStateEnv(t *testing.T) {
	e := newCheckEnv(t)
	e.writeNativeState(t, filepath.Join(e.root, ".demo-native", "state.env"), e.url)
	out, code := e.run(t, "admin login|machine identity", "--url", e.url)
	if code != 0 {
		t.Fatalf("want exit 0 reading .demo-native/state.env, got %d:\n%s", code, out)
	}
	if !strings.Contains(out, "credentials from") || !strings.Contains(out, "state.env") {
		t.Fatalf("check.sh did not say which state file it used:\n%s", out)
	}
	if pass, machine := e.api.seen(); pass != "native-admin-pw" || machine != "kx_machine_native" {
		t.Fatalf("state.env credentials not used: login=%q machine token=%q", pass, machine)
	}
}

func TestCheck_ExplicitStateFlag(t *testing.T) {
	e := newCheckEnv(t)
	state := filepath.Join(e.root, "elsewhere", "native.env")
	e.writeNativeState(t, state, e.url)
	out, code := e.run(t, "machine identity", "--url", e.url, "--state", state)
	if _, machine := e.api.seen(); code != 0 || machine != "kx_machine_native" {
		t.Fatalf("--state not honoured, exit %d, token %q:\n%s", code, machine, out)
	}
}

func TestCheck_StateForAnotherServerIsNotUsed(t *testing.T) {
	e := newCheckEnv(t)
	e.writeNativeState(t, filepath.Join(e.root, ".demo-native", "state.env"), "http://127.0.0.1:1")
	out, code := e.run(t, "machine identity", "--url", e.url)
	if code == 0 || strings.Contains(out, "credentials from") {
		t.Fatalf("a state file for a different server must not be used silently, exit %d:\n%s", code, out)
	}
}

func TestCheck_MissingStateFlagFileFailsFast(t *testing.T) {
	e := newCheckEnv(t)
	out, code := e.run(t, "health", "--url", e.url, "--state", filepath.Join(e.root, "nope.env"))
	if code != 1 || !strings.Contains(out, "no such file") {
		t.Fatalf("want exit 1 naming the missing file, got %d:\n%s", code, out)
	}
}

func TestCheck_FreshDemoStaysStrictOnNewUserAlert(t *testing.T) {
	e := newCheckEnv(t)
	e.writeNativeState(t, filepath.Join(e.root, ".demo-native", "state.env"), e.url)
	e.api.setAlerts(alert(1, "new_user", "low", "alice"))
	out, code := e.run(t, "admin login|no open anomalies", "--url", e.url)
	if code != 1 || !strings.Contains(out, "open anomaly alerts on a fresh demo") || !strings.Contains(out, "--used") {
		t.Fatalf("a fresh demo must FAIL on any open alert (and hint at --used), got %d:\n%s", code, out)
	}
}

func TestCheck_UsedDemoWarnsOnNewUserAndNewIP(t *testing.T) {
	e := newCheckEnv(t)
	e.writeNativeState(t, filepath.Join(e.root, ".demo-native", "state.env"), e.url)
	e.api.setAlerts(alert(1, "new_user", "low", "alice"), alert(2, "new_ip", "medium", "ci-app"))
	out, code := e.run(t, "admin login|no open anomalies", "--url", e.url, "--used")
	if code != 0 || !strings.Contains(out, "WARN") || !strings.Contains(out, "new_user/new_ip alerts from earlier reads are expected") ||
		!strings.Contains(out, "1 warning(s)") {
		t.Fatalf("--used must WARN (exit 0) on new_user/new_ip, got %d:\n%s", code, out)
	}
}

func TestCheck_UsedDemoStillFailsOnOtherAlerts(t *testing.T) {
	e := newCheckEnv(t)
	e.writeNativeState(t, filepath.Join(e.root, ".demo-native", "state.env"), e.url)
	e.api.setAlerts(alert(1, "new_user", "low", "alice"), alert(2, "volume_spike", "high", "ci-app"))
	out, code := e.run(t, "admin login|no open anomalies", "--url", e.url, "--used")
	if code != 1 || !strings.Contains(out, "volume_spike") {
		t.Fatalf("--used must still FAIL on a non-new_user/new_ip alert, got %d:\n%s", code, out)
	}
}

func TestCheck_ComplianceGapFreshStrictUsedWarns(t *testing.T) {
	e := newCheckEnv(t)
	e.writeNativeState(t, filepath.Join(e.root, ".demo-native", "state.env"), e.url)
	e.api.setGaps("secret-rotation", "anomaly-detection")
	e.api.setAlerts(alert(1, "new_ip", "high", "ci-app"))

	out, code := e.run(t, "admin login|compliance", "--url", e.url)
	if code != 1 || !strings.Contains(out, "exactly one gap") {
		t.Fatalf("a fresh demo must FAIL on the extra anomaly-detection gap, got %d:\n%s", code, out)
	}
	out, code = e.run(t, "admin login|compliance", "--url", e.url, "--used")
	if code != 0 || !strings.Contains(out, "WARN") || !strings.Contains(out, "expected; --used") {
		t.Fatalf("--used must WARN when the gap is caused by new_user/new_ip alerts only, got %d:\n%s", code, out)
	}
	e.api.setAlerts(alert(1, "new_ip", "high", "ci-app"), alert(2, "volume_spike", "high", "ci-app"))
	if out, code = e.run(t, "admin login|compliance", "--url", e.url, "--used"); code != 1 {
		t.Fatalf("--used must FAIL when another alert type is open, got %d:\n%s", code, out)
	}
}
