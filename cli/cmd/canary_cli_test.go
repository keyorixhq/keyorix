package cmd

// CLI half of the secret-leak canary oracle (internal/canary/PREREG.md).
// Builds the real binary, plants Secret-class canaries in argv, env, stdin and
// files, and scans stdout and stderr of failure, usage and debug paths. Each
// vector declares whether it must reach the fake servers (and the test asserts
// it): vectors with wantContact send the credential to a hostile fake server,
// the others cover the refusals and local errors that happen before any network
// use. Files the CLI writes under HOME are reported but not gated (a token
// store is by design).

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/canary"
)

func canarySeed() uint64 {
	if v := os.Getenv("CANARY_SEED"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	return 1
}

func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "keyorix")
	cmd := exec.Command("go", "build", "-o", bin, "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

type fakeServer struct {
	url      string
	requests atomic.Int64
	srv      *httptest.Server
}

func newFake(t *testing.T, mode string) *fakeServer {
	f := &fakeServer{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		switch mode {
		case "401":
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		case "500":
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"error":"internal"}`))
		case "html":
			w.WriteHeader(502)
			_, _ = w.Write([]byte("<html>bad gateway</html>"))
		case "badjson":
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"data":`))
		default:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": map[string]any{"message": "denied"}})
		}
	})
	f.srv = httptest.NewServer(h)
	t.Cleanup(f.srv.Close)
	f.url = f.srv.URL
	return f
}

func TestCLICanaryStdoutStderr(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLI and runs it about 100 times")
	}
	bin := buildCLI(t)
	seed := canarySeed()
	pw := canary.New("cli-pw", canary.Secret, seed, true)
	tok := canary.New("cli-tok", canary.Secret, seed+1, true)
	val := canary.New("cli-val", canary.Secret, seed+2, true)
	code := canary.New("cli-code", canary.Secret, seed+3, false)
	stdinC := canary.New("cli-stdin", canary.Secret, seed+4, true)
	sc := canary.NewScanner(pw, tok, val, code, stdinC)

	// closed port: connection refused
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + ln.Addr().String()
	_ = ln.Close()

	type vec struct {
		name        string
		args        []string
		env         map[string]string
		stdin       string
		wantContact bool
	}
	vecs := []vec{
		{"login-flag", []string{"login", "--username", "alice", "--password", pw.Raw}, nil, "", false},
		{"login-env", []string{"login", "--username", "alice"}, map[string]string{"KEYORIX_PASSWORD": pw.Raw}, "", true},
		{"login-mfa", []string{"login", "--username", "alice", "--password", pw.Raw, "--mfa-code", code.Raw}, nil, "", false},
		{"login-mfa-env", []string{"login", "--username", "alice"}, map[string]string{"KEYORIX_PASSWORD": pw.Raw, "KEYORIX_MFA_CODE": code.Raw}, "", true},
		{"login-stdin", []string{"login", "--username", "alice"}, nil, stdinC.Raw + "\n", true},
		{"secret-create-flag", []string{"secret", "create", "--name", "n", "--value", val.Raw}, map[string]string{"KEYORIX_TOKEN": tok.Raw}, "", false},
		{"secret-create-stdin", []string{"secret", "create", "--name", "n", "--from-file", "-"}, map[string]string{"KEYORIX_TOKEN": tok.Raw}, val.Raw, true},
		{"secret-update-flag", []string{"secret", "update", "--id", "1", "--value", val.Raw}, map[string]string{"KEYORIX_TOKEN": tok.Raw}, "", false},
		{"secret-update-stdin", []string{"secret", "update", "--id", "1", "--from-file", "-"}, map[string]string{"KEYORIX_TOKEN": tok.Raw}, val.Raw, true},
		{"secret-list-token", []string{"secret", "list"}, map[string]string{"KEYORIX_TOKEN": tok.Raw}, "", true},
		{"secret-list-token-debug", []string{"secret", "list"}, map[string]string{"KEYORIX_TOKEN": tok.Raw, "KEYORIX_DEBUG": "1"}, "", true},
		{"user-create-pw", []string{"user", "create", "--username", "u", "--email", "u@e.co", "--password", pw.Raw}, map[string]string{"KEYORIX_TOKEN": tok.Raw}, "", false},
		{"user-create-env", []string{"user", "create", "--username", "u", "--email", "u@e.co"}, map[string]string{"KEYORIX_TOKEN": tok.Raw, "KEYORIX_INITIAL_PASSWORD": pw.Raw}, "", true},
		{"mfa-activate", []string{"mfa", "activate", "--password", pw.Raw, "--code", code.Raw}, map[string]string{"KEYORIX_TOKEN": tok.Raw}, "", false},
		{"mfa-activate-env", []string{"mfa", "activate"}, map[string]string{"KEYORIX_TOKEN": tok.Raw, "KEYORIX_PASSWORD": pw.Raw, "KEYORIX_MFA_CODE": code.Raw}, "", true},
		{"bad-flag-with-secret", []string{"secret", "create", "--bogus", val.Raw, "--value", val.Raw}, nil, "", false},
		{"bad-command-with-secret", []string{pw.Raw, "--password", pw.Raw}, nil, "", false},
		{"bad-type", []string{"secret", "create", "--name", "n", "--value", val.Raw, "--max-reads", pw.Raw}, nil, "", false},
		{"bad-expires", []string{"secret", "create", "--name", "n", "--value", val.Raw, "--expires", tok.Raw}, map[string]string{"KEYORIX_TOKEN": tok.Raw}, "", false},
		{"token-file-missing", []string{"secret", "list"}, map[string]string{"KEYORIX_TOKEN_FILE": "/nonexistent/" + tok.Raw}, "", false},
		{"help-with-env", []string{"login", "--help"}, map[string]string{"KEYORIX_PASSWORD": pw.Raw, "KEYORIX_TOKEN": tok.Raw}, "", false},
	}
	servers := map[string]string{"dead": dead}
	fakes := map[string]*fakeServer{}
	for _, m := range []string{"401", "500", "html", "badjson", "json"} {
		fakes[m] = newFake(t, m)
		servers[m] = fakes[m].url
	}

	// Classified expected-non-secret echoes (deterministic, replayed 3x), one row
	// per exact (vector, canary label, surface): the canary sits in a position
	// that is not a credential argument, and the standard library/cobra error
	// text quotes the offending token back. Any other hit in these vectors fails.
	type echoKey struct{ vector, label, surface string }
	expectedEcho := map[echoKey]string{
		{"bad-command-with-secret", "cli-pw", "stderr"}: "cobra quotes an unknown command word",
		{"bad-type", "cli-pw", "stderr"}:                "cobra quotes an unparsable value of a numeric flag",
		{"token-file-missing", "cli-tok", "stderr"}:     "os error quotes the missing file path",
	}
	usedEcho := map[echoKey]bool{}
	var findings []string
	echoes := 0
	runs := 0
	for _, v := range vecs {
		for sname, surl := range servers {
			home := t.TempDir()
			var before int64
			if f := fakes[sname]; f != nil {
				before = f.requests.Load()
			}
			cmd := exec.Command(bin, v.args...)
			cmd.Env = []string{"HOME=" + home, "TMPDIR=" + home, "PATH=" + os.Getenv("PATH"), "KEYORIX_SERVER=" + surl, "NO_COLOR=1"}
			for k, e := range v.env {
				cmd.Env = append(cmd.Env, k+"="+e)
			}
			cmd.Stdin = strings.NewReader(v.stdin)
			var so, se strings.Builder
			cmd.Stdout, cmd.Stderr = &so, &se
			done := make(chan struct{})
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			go func() { _ = cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				_ = cmd.Process.Kill()
				<-done
				t.Logf("timeout (killed): %s/%s", v.name, sname)
			}
			runs++
			if f := fakes[sname]; f != nil {
				if contacted := f.requests.Load() > before; contacted != v.wantContact {
					t.Errorf("vector %s against server %s: contacted the server=%v, want %v", v.name, sname, contacted, v.wantContact)
				}
			}
			for _, h := range append(sc.Scan("stdout", []byte(so.String())), sc.Scan("stderr", []byte(se.String()))...) {
				k := echoKey{v.name, h.Label, h.Surface}
				if _, ok := expectedEcho[k]; ok {
					usedEcho[k] = true
					echoes++
					continue
				}
				findings = append(findings, fmt.Sprintf("%s|%s|%s|%s|%s", h.Surface, v.name, sname, h.Label, h.Variant))
			}
			if strings.Contains(strings.Join(v.args, " "), "panic") || strings.Contains(se.String(), "goroutine ") {
				findings = append(findings, "PANIC|"+v.name+"|"+sname)
			}
			// files the CLI left behind: reported, not gated
			_ = filepath.Walk(home, func(p string, fi os.FileInfo, err error) error {
				if err != nil || fi.IsDir() {
					return nil
				}
				b, _ := os.ReadFile(p)
				for _, h := range sc.Scan("file", b) {
					t.Logf("file-note: %s/%s %s label=%s (stored by design? not gated)", v.name, sname, filepath.Base(p), h.Label)
				}
				return nil
			})
		}
	}
	if os.Getenv("CANARY_OUT") != "" {
		b, _ := json.MarshalIndent(findings, "", " ")
		_ = os.WriteFile(os.Getenv("CANARY_OUT"), b, 0o600)
	}
	t.Logf("runs=%d findings=%d expected-echo-hits=%d", runs, len(findings), echoes)
	for _, f := range findings {
		t.Errorf("CLI leak candidate: %s", f)
	}
	for k, why := range expectedEcho {
		if !usedEcho[k] {
			t.Errorf("expected echo %+v (%s) matched nothing: remove the row", k, why)
		}
	}
}

// Planted-leak self-test: a program that echoes its argv must be caught.
func TestCLICanaryPlantedLeakDetected(t *testing.T) {
	pw := canary.New("plant", canary.Secret, 99, true)
	sc := canary.NewScanner(pw)
	out, _ := exec.Command("echo", pw.Raw).CombinedOutput()
	if len(sc.Scan("stdout", out)) == 0 {
		t.Fatal("planted echo leak not detected")
	}
	out, _ = exec.Command("echo", "clean").CombinedOutput()
	if len(sc.Scan("stdout", out)) != 0 {
		t.Fatal("negative control produced a hit")
	}
}
