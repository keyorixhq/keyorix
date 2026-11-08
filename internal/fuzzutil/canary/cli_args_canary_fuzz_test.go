package canary_test

// cli_args_canary_fuzz_test.go -- FuzzCLIArgsCanaryLeak.
//
// Lives here, not in cli/cmd, so the CLI module's own dependency graph stays free of
// the main module (INV-CLI-01) and because it only ever needs the built binary.
//
// Runs the real keyorix binary with a canary in flag values, environment variables
// and standard input, against a fake server (httptest over loopback, no other
// network), and asserts the canary reaches neither standard output, standard error
// nor any file the process leaves behind, outside cliCanaryRules. Each execution
// has its own HOME and server, so nothing carries over between executions. Every
// execution also proves the capture works by revealing a control secret through
// `secret get --ref`.
//
// TestCLICanaryStdoutStderr is the deterministic sweep of fixed vectors; this target
// adds a fuzzed extra-argument tail, server response modes, fragment matching and
// the file scan as a gated channel.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/canary"
)

const (
	cliChanFile = "file:"

	// cliSecretPlaceholder, cliTokenPlaceholder and cliMetaPlaceholder are replaced
	// with the canaries in a vector's arguments, environment and standard input.
	cliSecretPlaceholder = "@S@"
	cliTokenPlaceholder  = "@T@"
	cliMetaPlaceholder   = "@M@"
	cliServerPlaceholder = "@U@"
)

// cliCanaryRules is the whole allowlist for the fuzzed invocation. A secret canary
// has no permitted channel. The control reveal is checked separately.
func cliCanaryRules() *canary.Allowlist {
	return canary.NewAllowlist(
		canary.Rule{ID: "meta-stderr", Channel: canary.ChannelStderr, MetadataOnly: true, Why: "cobra and strconv quote a bad argument back to the user who typed it"},
	)
}

type cliFuzzVector struct {
	name     string
	args     []string
	env      map[string]string
	stdin    string
	insecure bool // sets KEYORIX_ALLOW_INSECURE_SECRET_FLAGS, to get past the refusal of secret flags
}

var cliFuzzVectors = []cliFuzzVector{
	{name: "login-flag", args: []string{"login", "--username", "alice", "--password", cliSecretPlaceholder}},
	{name: "login-flag-allowed", args: []string{"login", "--username", "alice", "--password", cliSecretPlaceholder}, insecure: true},
	{name: "login-env", args: []string{"login", "--username", "alice"}, env: map[string]string{"KEYORIX_PASSWORD": cliSecretPlaceholder}},
	{name: "login-mfa-env", args: []string{"login", "--username", "alice"}, env: map[string]string{"KEYORIX_PASSWORD": cliSecretPlaceholder, "KEYORIX_MFA_CODE": cliTokenPlaceholder}},
	{name: "login-stdin", args: []string{"login", "--username", "alice"}, stdin: cliSecretPlaceholder + "\n"},
	{name: "secret-create-flag", args: []string{"secret", "create", "--name", cliMetaPlaceholder, "--value", cliSecretPlaceholder}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder}},
	{name: "secret-create-flag-allowed", args: []string{"secret", "create", "--name", cliMetaPlaceholder, "--value", cliSecretPlaceholder}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder}, insecure: true},
	{name: "secret-create-stdin", args: []string{"secret", "create", "--name", cliMetaPlaceholder, "--from-file", "-"}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder}, stdin: cliSecretPlaceholder},
	{name: "secret-update-flag-allowed", args: []string{"secret", "update", "--id", "1", "--value", cliSecretPlaceholder}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder}, insecure: true},
	{name: "secret-update-stdin", args: []string{"secret", "update", "--id", "1", "--from-file", "-"}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder}, stdin: cliSecretPlaceholder},
	{name: "secret-list", args: []string{"secret", "list"}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder}},
	{name: "secret-list-debug", args: []string{"secret", "list"}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder, "KEYORIX_DEBUG": "1"}},
	{name: "secret-get-by-name", args: []string{"secret", "get", "--name", cliMetaPlaceholder}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder}},
	{name: "user-create-env", args: []string{"user", "create", "--username", "u", "--email", "u@e.co"}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder, "KEYORIX_INITIAL_PASSWORD": cliSecretPlaceholder}},
	{name: "user-create-flag-allowed", args: []string{"user", "create", "--username", "u", "--email", "u@e.co", "--password", cliSecretPlaceholder}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder}, insecure: true},
	{name: "mfa-activate-env", args: []string{"mfa", "activate"}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder, "KEYORIX_PASSWORD": cliSecretPlaceholder, "KEYORIX_MFA_CODE": cliSecretPlaceholder}},
	{name: "change-password-env", args: []string{"change-password"}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder, "KEYORIX_CURRENT_PASSWORD": cliSecretPlaceholder, "KEYORIX_NEW_PASSWORD": cliSecretPlaceholder + "x"}},
	{name: "dynamic-dsn-env", args: []string{"dynamic-secret", "create", "--name", "n", "--project-id", "1", "--backend", "postgres"}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder, "KEYORIX_DYNAMIC_ADMIN_DSN": "postgres://u:" + cliSecretPlaceholder + "@h/db"}},
	{name: "system-init-env", args: []string{"system", "init", "--server", cliServerPlaceholder}, env: map[string]string{"KEYORIX_ADMIN_PASSWORD": cliSecretPlaceholder, "KEYORIX_BOOTSTRAP_TOKEN": cliTokenPlaceholder}},
	{name: "help-with-env", args: []string{"login", "--help"}, env: map[string]string{"KEYORIX_PASSWORD": cliSecretPlaceholder, "KEYORIX_TOKEN": cliTokenPlaceholder}},
	{name: "unknown-flag-with-secret-env", args: []string{"secret", "create", "--bogus", cliMetaPlaceholder}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder}},
	{name: "unknown-command", args: []string{cliMetaPlaceholder}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder}},
	{name: "bad-int-flag", args: []string{"secret", "get", "--id", cliMetaPlaceholder}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder}},
	{name: "token-file-missing", args: []string{"secret", "list"}, env: map[string]string{"KEYORIX_TOKEN_FILE": "/nonexistent/" + cliMetaPlaceholder}},
	{name: "doctor-env", args: []string{"doctor"}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder}},
	{name: "status-env", args: []string{"status"}, env: map[string]string{"KEYORIX_TOKEN": cliTokenPlaceholder}},
}

// Fake server response modes.
const (
	cliModeUnauthorized = iota
	cliModeServerError
	cliModeHTML
	cliModeBadJSON
	cliModeDenied
	cliModeSuccessShape
	cliModeCount
)

const (
	cliFakeSecretName = "fake-secret-name"
	cliFakeSessionTok = "fake-server-issued-session"
)

type cliFakeServer struct {
	srv *httptest.Server
	// commandRequests counts requests other than the skew check and the control
	// reveal: proof that the fuzzed command itself reached the network.
	commandRequests atomic.Int64
}

// newCLIFakeServer answers /api/v1/version properly so the skew check passes and the
// command reaches its own request, and answers everything else by mode. reveal is
// returned for a value read in every mode, so the control has a fixed path.
func newCLIFakeServer(t testing.TB, mode int, reveal string) *cliFakeServer {
	t.Helper()
	fake := &cliFakeServer{}
	fake.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/version"):
			_ = json.NewEncoder(w).Encode(map[string]any{"api_version": 1})
			return
		case strings.Contains(r.URL.Path, "/secrets/value"):
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"secret": map[string]any{"id": 1, "name": cliFakeSecretName}, "value": reveal}})
			return
		}
		fake.commandRequests.Add(1)
		switch mode % cliModeCount {
		case cliModeUnauthorized:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		case cliModeServerError:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal"}`))
		case cliModeHTML:
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("<html>bad gateway</html>"))
		case cliModeBadJSON:
			_, _ = w.Write([]byte(`{"data":`))
		case cliModeDenied:
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": map[string]any{"message": "denied"}})
		case cliModeSuccessShape:
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": 1, "name": cliFakeSecretName, "token": cliFakeSessionTok, "session_token": cliFakeSessionTok}})
		}
	}))
	t.Cleanup(fake.srv.Close)
	return fake
}

// cliRun is one execution of the fuzzed vector and its control.
type cliRun struct {
	scanner *canary.Scanner
	allow   *canary.Allowlist
	bin     string
	home    string
	server  string
	fake    *cliFakeServer

	secret, token, meta, control canary.Canary
	findings                     []string
}

// sanitizeExtraArgs turns the fuzz tail into arguments. exec.Command rejects a NUL
// in an argument, and a very long tail only slows the run down.
func sanitizeExtraArgs(tail []byte) []string {
	if len(tail) > 256 {
		tail = tail[:256]
	}
	var out []string
	for part := range strings.SplitSeq(string(tail), "\x00") {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func (r *cliRun) fill(s string) string {
	s = strings.ReplaceAll(s, cliSecretPlaceholder, r.secret.Raw)
	s = strings.ReplaceAll(s, cliTokenPlaceholder, r.token.Raw)
	s = strings.ReplaceAll(s, cliServerPlaceholder, r.server)
	return strings.ReplaceAll(s, cliMetaPlaceholder, r.meta.Raw)
}

// invoke runs the binary. A hang fails the run: an input that blocks a CLI forever
// is itself a defect, and an unfinished process shows no output to judge.
func (r *cliRun) invoke(args []string, env map[string]string, stdin string, insecure bool) (stdout, stderr []byte, crashed bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Dir = r.home
	cmd.Env = []string{"HOME=" + r.home, "TMPDIR=" + r.home, "PATH=" + os.Getenv("PATH"), "KEYORIX_SERVER=" + r.server, "NO_COLOR=1", "XDG_CONFIG_HOME=" + filepath.Join(r.home, "config")}
	if insecure {
		cmd.Env = append(cmd.Env, "KEYORIX_ALLOW_INSECURE_SECRET_FLAGS=1")
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdin = strings.NewReader(stdin)
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return nil, nil, false, fmt.Errorf("command timed out: %v", args)
	}
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		return nil, nil, false, fmt.Errorf("could not run the binary: %w", runErr)
	}
	return []byte(so.String()), []byte(se.String()), strings.Contains(se.String(), "goroutine "), nil
}

func (r *cliRun) judge(origin, channel string, data []byte) {
	for _, h := range r.scanner.Scan(channel, data) {
		if r.allow.Permit(h, origin) == "" {
			r.findings = append(r.findings, fmt.Sprintf("vector=%s %s", origin, h))
		}
	}
}

// judgeFiles scans every file the process left under its HOME.
func (r *cliRun) judgeFiles(origin string) error {
	return filepath.WalkDir(r.home, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(r.home, p)
		if err != nil {
			return err
		}
		r.judge(origin, cliChanFile+rel, data)
		return nil
	})
}

// control reveals a secret through the real command and requires its canary in the
// output. Without it, a clean result could mean the capture is broken.
func (r *cliRun) controlReveal() error {
	stdout, _, _, err := r.invoke([]string{"secret", "get", "--ref", "p/e/" + cliFakeSecretName}, map[string]string{"KEYORIX_TOKEN": "control-token"}, "", false)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(r.scanner.Scan("reveal", stdout), func(h canary.Hit) bool { return h.Label == r.control.Label }) {
		return fmt.Errorf("the reveal did not print the control canary; stdout: %q", stdout)
	}
	return nil
}

type cliCanaryInput struct {
	vector, mode uint8
	tail         []byte
}

func newCLIRun(t testing.TB, bin string, in cliCanaryInput, allow *canary.Allowlist) *cliRun {
	t.Helper()
	seed := append([]byte{in.vector, in.mode}, in.tail...)
	r := &cliRun{
		scanner: canary.NewScanner(), allow: allow, bin: bin, home: t.TempDir(),
		secret: canary.New("secret", canary.Secret, seed, in.mode%2 == 1), token: canary.New("token", canary.Secret, seed, false),
		meta: canary.New("meta", canary.Metadata, seed, false), control: canary.New("control", canary.Secret, seed, true),
	}
	r.scanner.Add(r.secret)
	r.scanner.Add(r.token)
	r.scanner.Add(r.meta)
	r.scanner.Add(r.control)
	r.fake = newCLIFakeServer(t, int(in.mode), r.control.Raw)
	r.server = r.fake.srv.URL
	return r
}

func runCLICanary(t testing.TB, bin string, in cliCanaryInput, allow *canary.Allowlist) (*cliRun, error) {
	t.Helper()
	r := newCLIRun(t, bin, in, allow)
	vec := cliFuzzVectors[int(in.vector)%len(cliFuzzVectors)]
	if err := r.controlReveal(); err != nil {
		return r, fmt.Errorf("INVALID RUN: %w", err)
	}
	args := make([]string, 0, len(vec.args)+4)
	for _, a := range vec.args {
		args = append(args, r.fill(a))
	}
	args = append(args, sanitizeExtraArgs(in.tail)...)
	env := make(map[string]string, len(vec.env))
	for k, v := range vec.env {
		env[k] = r.fill(v)
	}
	stdout, stderr, crashed, err := r.invoke(args, env, r.fill(vec.stdin), vec.insecure)
	if err != nil {
		return r, err
	}
	if crashed {
		r.findings = append(r.findings, fmt.Sprintf("vector=%s the CLI crashed:\n%s", vec.name, stderr))
	}
	r.judge(vec.name, canary.ChannelStdout, stdout)
	r.judge(vec.name, canary.ChannelStderr, stderr)
	if err := r.judgeFiles(vec.name); err != nil {
		return r, fmt.Errorf("INVALID RUN: scanning the home directory: %w", err)
	}
	return r, nil
}

// buildCanaryCLI builds the binary from the cli module. The module is outside the
// repository's go.work, which is why the build has GOWORK=off. Living in the main
// module keeps this harness out of the CLI's own dependency graph (INV-CLI-01).
func buildCanaryCLI(tb testing.TB, dir string) string {
	tb.Helper()
	bin := filepath.Join(dir, "keyorix")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = filepath.Join("..", "..", "..", "cli")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		tb.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func addCLICanarySeeds(f *testing.F) {
	for i := range cliFuzzVectors {
		f.Add(uint8(i), uint8(i%cliModeCount), []byte(nil))
	}
	f.Add(uint8(5), uint8(cliModeSuccessShape), []byte("--description\x00x\x00--tags\x00a,b"))
	f.Add(uint8(10), uint8(cliModeHTML), []byte("--project-id\x00notanumber"))
}

// FuzzCLIArgsCanaryLeak fails when a secret passed to the real CLI through flags,
// environment or standard input reaches its output or a file it leaves behind.
func FuzzCLIArgsCanaryLeak(f *testing.F) {
	bin := buildCanaryCLI(f, f.TempDir())
	addCLICanarySeeds(f)
	f.Fuzz(func(t *testing.T, vector, mode uint8, tail []byte) {
		r, err := runCLICanary(t, bin, cliCanaryInput{vector, mode, tail}, cliCanaryRules())
		if err != nil {
			t.Fatal(err)
		}
		if len(r.findings) > 0 {
			t.Fatalf("CANARY LEAK (%d):\n%s", len(r.findings), strings.Join(r.findings, "\n"))
		}
	})
}

// TestCLIArgsCanaryOracle is the red-proof: a wrapper script standing in for the
// binary writes a canary into one channel and then runs the real binary, so the real
// command still executes and the controls still pass. Nothing in the product changes.
func TestCLIArgsCanaryOracle(t *testing.T) {
	dir := t.TempDir()
	bin := buildCanaryCLI(t, dir)
	wrapper := func(t *testing.T, script string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "keyorix-wrapper")
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\nexec "+bin+" \"$@\"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	// Vector 2 is login-env; KEYORIX_PASSWORD holds the secret canary and the mode
	// makes the login fail, so the wrapper is the only possible source of a leak.
	in := cliCanaryInput{vector: 2, mode: cliModeUnauthorized}
	cases := []struct {
		name, script, want string
	}{
		{"stdout", `echo "$KEYORIX_PASSWORD"`, canary.ChannelStdout},
		{"stderr", `echo "$KEYORIX_PASSWORD" >&2`, canary.ChannelStderr},
		{"file", `echo "$KEYORIX_PASSWORD" > "$HOME/leak.log"`, cliChanFile + "leak.log"},
		{"base64-in-stderr", `printf '%s' "$KEYORIX_PASSWORD" | base64 >&2`, canary.ChannelStderr},
		{"fragment-in-stdout", `echo "$KEYORIX_PASSWORD" | cut -c10-30`, canary.ChannelStdout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := runCLICanary(t, wrapper(t, tc.script), in, cliCanaryRules())
			if err != nil {
				t.Fatal(err)
			}
			want := "channel=" + tc.want + " "
			if !slices.ContainsFunc(r.findings, func(s string) bool { return strings.Contains(s, want) }) {
				t.Fatalf("planted leak on %s was not reported; findings: %v", tc.want, r.findings)
			}
		})
	}
	t.Run("vectors-take-effect", func(t *testing.T) {
		allow := cliCanaryRules()
		var silent []string
		for i, vec := range cliFuzzVectors {
			r, err := runCLICanary(t, bin, cliCanaryInput{vector: uint8(i), mode: cliModeSuccessShape}, allow)
			if err != nil {
				t.Fatalf("%s: %v", vec.name, err)
			}
			if len(r.findings) != 0 {
				t.Errorf("%s reported: %v", vec.name, r.findings)
			}
			if r.fake.commandRequests.Load() == 0 {
				silent = append(silent, vec.name)
			}
		}
		// These fail before any network use by design: a refused flag, a local usage
		// error, help output, or a local diagnostic. Any other vector has to reach the
		// server or it is not exercising the path it is named for.
		wantSilent := []string{"login-flag", "secret-create-flag", "help-with-env", "unknown-flag-with-secret-env", "unknown-command", "bad-int-flag", "token-file-missing"}
		slices.Sort(wantSilent)
		slices.Sort(silent)
		if !slices.Equal(silent, wantSilent) {
			t.Errorf("vectors that never reached the server: got %v, want %v", silent, wantSilent)
		}
		if unused := allow.Unused(); len(unused) > 0 {
			t.Errorf("allowlist rules no vector needed: %v", unused)
		}
	})
	t.Run("clean-run-is-clean", func(t *testing.T) {
		r, err := runCLICanary(t, bin, in, cliCanaryRules())
		if err != nil {
			t.Fatal(err)
		}
		if len(r.findings) != 0 {
			t.Fatalf("clean run reported: %v", r.findings)
		}
	})
	t.Run("crash-is-a-finding", func(t *testing.T) {
		r, err := runCLICanary(t, wrapper(t, `echo "goroutine 1 [running]:" >&2`), in, cliCanaryRules())
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(r.findings, func(s string) bool { return strings.Contains(s, "crashed") }) {
			t.Fatalf("a crash was not reported: %v", r.findings)
		}
	})
}
