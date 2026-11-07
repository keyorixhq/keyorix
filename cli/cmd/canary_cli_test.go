package cmd

// CLI half of the secret-leak canary oracle (internal/canary/PREREG.md).
// Builds the real binary, plants Secret-class canaries in argv, env, stdin and
// files, drives failure/usage/debug paths against hostile fake servers and
// scans stdout and stderr. Files the CLI writes under HOME are reported but
// not gated (a token store is by design).

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
	url  string
	seen atomic.Int64
	srv  *httptest.Server
}

func newFake(t *testing.T, mode string, needle string) *fakeServer {
	f := &fakeServer{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 1<<16)
		n, _ := r.Body.Read(b)
		if strings.Contains(string(b[:n])+r.URL.RawQuery+r.Header.Get("Authorization"), needle) {
			f.seen.Add(1)
		}
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
	ln.Close()

	type vec struct {
		name  string
		args  []string
		env   map[string]string
		stdin string
	}
	vecs := []vec{
		{"login-flag", []string{"login", "--username", "alice", "--password", pw.Raw}, nil, ""},
		{"login-env", []string{"login", "--username", "alice"}, map[string]string{"KEYORIX_PASSWORD": pw.Raw}, ""},
		{"login-mfa", []string{"login", "--username", "alice", "--password", pw.Raw, "--mfa-code", code.Raw}, nil, ""},
		{"login-stdin", []string{"login", "--username", "alice"}, nil, stdinC.Raw + "\n"},
		{"secret-create-flag", []string{"secret", "create", "--name", "n", "--value", val.Raw}, map[string]string{"KEYORIX_TOKEN": tok.Raw}, ""},
		{"secret-create-stdin", []string{"secret", "create", "--name", "n", "--from-file", "-"}, map[string]string{"KEYORIX_TOKEN": tok.Raw}, val.Raw},
		{"secret-update-flag", []string{"secret", "update", "--id", "1", "--value", val.Raw}, map[string]string{"KEYORIX_TOKEN": tok.Raw}, ""},
		{"secret-list-token", []string{"secret", "list"}, map[string]string{"KEYORIX_TOKEN": tok.Raw}, ""},
		{"secret-list-token-debug", []string{"secret", "list"}, map[string]string{"KEYORIX_TOKEN": tok.Raw, "KEYORIX_DEBUG": "1"}, ""},
		{"user-create-pw", []string{"user", "create", "--username", "u", "--email", "u@e.co", "--password", pw.Raw}, map[string]string{"KEYORIX_TOKEN": tok.Raw}, ""},
		{"mfa-activate", []string{"mfa", "activate", "--password", pw.Raw, "--code", code.Raw}, map[string]string{"KEYORIX_TOKEN": tok.Raw}, ""},
		{"bad-flag-with-secret", []string{"secret", "create", "--bogus", val.Raw, "--value", val.Raw}, nil, ""},
		{"bad-command-with-secret", []string{pw.Raw, "--password", pw.Raw}, nil, ""},
		{"bad-type", []string{"secret", "create", "--name", "n", "--value", val.Raw, "--max-reads", pw.Raw}, nil, ""},
		{"bad-expires", []string{"secret", "create", "--name", "n", "--value", val.Raw, "--expires", tok.Raw}, map[string]string{"KEYORIX_TOKEN": tok.Raw}, ""},
		{"token-file-missing", []string{"secret", "list"}, map[string]string{"KEYORIX_TOKEN_FILE": "/nonexistent/" + tok.Raw}, ""},
		{"help-with-env", []string{"login", "--help"}, map[string]string{"KEYORIX_PASSWORD": pw.Raw, "KEYORIX_TOKEN": tok.Raw}, ""},
	}
	servers := map[string]string{"dead": dead}
	for _, m := range []string{"401", "500", "html", "badjson", "json"} {
		servers[m] = newFake(t, m, "kxc").url
	}

	// Classified expected-non-secret echoes (deterministic, replayed 3x): the
	// canary sits in a position that is not a credential argument, and the
	// standard library/cobra error text quotes the offending token back.
	expectedEcho := map[string]string{
		"bad-command-with-secret": "cobra quotes an unknown command word",
		"bad-type":                "cobra quotes an unparsable value of a numeric flag",
		"token-file-missing":      "os error quotes the missing file path",
	}
	var findings []string
	echoes := 0
	runs := 0
	for _, v := range vecs {
		for sname, surl := range servers {
			home := t.TempDir()
			cmd := exec.Command(bin, v.args...)
			cmd.Env = []string{"HOME=" + home, "TMPDIR=" + home, "PATH=" + os.Getenv("PATH"), "KEYORIX_SERVER=" + surl, "NO_COLOR=1"}
			for k, e := range v.env {
				cmd.Env = append(cmd.Env, k+"="+e)
			}
			cmd.Stdin = strings.NewReader(v.stdin)
			var so, se strings.Builder
			cmd.Stdout, cmd.Stderr = &so, &se
			done := make(chan error, 1)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			go func() { done <- cmd.Wait() }()
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				_ = cmd.Process.Kill()
				<-done
				t.Logf("timeout (killed): %s/%s", v.name, sname)
			}
			runs++
			for _, h := range append(sc.Scan("stdout", []byte(so.String())), sc.Scan("stderr", []byte(se.String()))...) {
				if _, ok := expectedEcho[v.name]; ok {
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
