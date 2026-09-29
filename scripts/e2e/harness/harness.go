//go:build e2e

// Package harness is the shared fresh-install boot/bootstrap/port/cleanup
// mechanism for this repo's Go-based e2e drivers: SESSION-I's feature smoke
// suite (scripts/e2e) and SESSION-N's customer-journey suite
// (scripts/e2e/journeys). It boots a REAL keyorix-server binary (built from
// this checkout) against a freshly migrated database -- SQLite by default,
// PostgreSQL when the caller supplies a DBBackend with a postgres
// configExtra -- bootstraps an admin exactly the way a real operator would
// (admin init / admin encryption init / admin migrate / start / POST
// system/init, the same sequence scripts/smoke.sh and
// server/admin_recover_admin_integration_test.go's bootstrapAdminViaHTTP
// already use and have proven works).
//
// Extracted from scripts/e2e/harness.go (a pure move, no behavior change) so
// two independent test packages share one boot sequence instead of each
// maintaining its own -- see docs/TESTING_GUIDE.md's "Fresh-install /
// real-backend E2E smoke" and "Customer journeys" sections.
//
// Excluded from the default build (this whole package requires the `e2e`
// build tag) because it shells out to `go build`, spawns real server
// subprocesses, binds real TCP ports, and (for the PostgreSQL leg) requires
// a real Postgres instance -- unsuitable for `go test ./...`'s default fast
// inner loop.
package harness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── Binary build (once per test binary run, shared across SQLite/Postgres legs) ──

var (
	buildOnce    sync.Once
	serverBinary string
	cliBinary    string
	buildErr     error
)

// RepoRoot walks up from this file's own directory to find go.mod, so the
// build works regardless of how `go test` was invoked (cwd-independent, same
// approach as server/admin_integration_test.go's findServerRepoRoot).
func RepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod) walking up from caller's package")
		}
		dir = parent
	}
}

// BuildBinaries compiles the real keyorix-server and keyorix (CLI) binaries
// exactly once for the whole `go test` run -- every smoke leg (SQLite,
// Postgres) exercises the identical build; paying the build cost twice would
// only slow the suite down, never change what's tested.
func BuildBinaries(t *testing.T) (server, cli string) {
	t.Helper()
	buildOnce.Do(func() {
		root := RepoRoot(t)
		dir, err := os.MkdirTemp("", "keyorix-e2e-bin-*")
		if err != nil {
			buildErr = fmt.Errorf("create build tmpdir: %w", err)
			return
		}

		serverPath := filepath.Join(dir, "keyorix-server")
		cmd := exec.Command("go", "build", "-o", serverPath, "./server") // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e harness itself built or downloaded, with the harness's own fixed arguments; no external input reaches it
		cmd.Dir = root
		if out, berr := cmd.CombinedOutput(); berr != nil {
			buildErr = fmt.Errorf("build keyorix-server: %w\n%s", berr, out)
			return
		}

		cliPath := filepath.Join(dir, "keyorix")
		cliCmd := exec.Command("go", "build", "-o", cliPath, ".") // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e harness itself built or downloaded, with the harness's own fixed arguments; no external input reaches it
		cliCmd.Dir = filepath.Join(root, "cli")
		cliCmd.Env = append(os.Environ(), "GOWORK=off")
		if out, berr := cliCmd.CombinedOutput(); berr != nil {
			buildErr = fmt.Errorf("build keyorix (cli): %w\n%s", berr, out)
			return
		}

		serverBinary, cliBinary = serverPath, cliPath
	})
	if buildErr != nil {
		t.Fatalf("%v", buildErr)
	}
	return serverBinary, cliBinary
}

// ── Server lifecycle ──────────────────────────────────────────────────────

// DBBackend describes which storage backend a smoke leg targets.
type DBBackend struct {
	Name string // "sqlite" or "postgres", used only in test/failure output
	// ConfigExtra is the storage: block appended to the generated config,
	// e.g. "storage:\n  type: sqlite\n  database:\n    path: keyorix.db\n"
	// for sqlite, or the postgres field-by-field form for postgres. Empty
	// means keep whatever `admin init` generated (sqlite default).
	ConfigExtra string
	// ExtraEnv carries backend-specific secrets that must never land in the
	// config file (e.g. KEYORIX_DB_PASSWORD for postgres).
	ExtraEnv []string
	// VerifyAuditFlag is the --db or --pg-dsn flag verify-audit needs to open
	// the same database directly, without the running server's lock.
	VerifyAuditFlag func(dir string) []string
}

// Server is a running keyorix-server subprocess plus everything the caller
// needs to talk to it and clean it up.
type Server struct {
	T          *testing.T
	Cmd        *exec.Cmd
	Dir        string
	ConfigPath string
	BaseURL    string
	Binary     string
	Env        []string
	LogPath    string
	Backend    DBBackend
}

// FreeTCPPort returns a port number no listener is bound to (same approach
// as server/admin_integration_test.go's freeTCPPort) -- avoids hardcoding a
// port that could collide with a real dev server, another test run, or the
// SQLite and Postgres legs running back to back.
func FreeTCPPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free TCP port: %v", err)
	}
	defer l.Close() //nolint:errcheck
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

// portLineRe matches server.http.port's value specifically -- anchored to
// the "enabled: true" line immediately above it in the generated template
// (configs/keyorix.yaml.tpl), not a bare `port: "\d+"` pattern. A bare
// pattern also matches storage.database.port (written by a PostgreSQL
// backend's ConfigExtra, e.g. `port: "15433"`) and server.grpc.port (whose
// own "enabled: false" line would need excluding some other way) -- both
// at the exact same indentation depth as server.http.port, so a
// content-blind regex silently rewrites the WRONG port whenever a Postgres
// backend or a second rewrite (the upgrade-path test picks a second free
// port for the NEW binary after the OLD binary already rewrote it once) is
// in play. grpc defaults to "enabled: false", so anchoring to
// "enabled: true" uniquely selects http's port even though grpc has the
// identical enabled/port shape.
var portLineRe = regexp.MustCompile(`(enabled: true\n\s*port: )"\d+"`)

// BootstrapAdminPassword deliberately shares no substring with the
// bootstrap admin's username/email/display_name (see StartServer's
// /system/init call) -- internal/core/rules.DefaultPasswordPolicy rejects
// any password containing the account's username/email/display name.
const BootstrapAdminPassword = "Quartz-Falcon-77-Ridge!"

// SmokeUserPassword is the second (non-admin) test user's password, same
// "shares no substring with username/email/display_name" constraint as
// BootstrapAdminPassword above -- that account is named "e2esmokeuser".
const SmokeUserPassword = "Cobalt-Harbor-42-Ember!"

// StartServer runs the exact operator-facing bootstrap sequence QUICK_START.md
// documents and scripts/smoke.sh already proves works end to end: admin init
// -> admin encryption init -> admin migrate -> start the server -> poll
// /health -> POST /system/init. Returns a *Server the caller must Close().
func StartServer(t *testing.T, binary string, backend DBBackend) *Server {
	t.Helper()
	dir := t.TempDir()
	env := append([]string{
		"HOME=" + dir,
		"PATH=" + os.Getenv("PATH"),
		"KEYORIX_MASTER_PASSWORD=e2e-smoke-master-password-" + backend.Name,
	}, backend.ExtraEnv...)

	configPath := "./keyorix.yaml"

	run := func(args ...string) {
		t.Helper()
		out, err := RunAdminCmd(binary, dir, env, args...)
		if err != nil {
			t.Fatalf("keyorix-server admin %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	run("init", "--config", configPath)

	if backend.ConfigExtra != "" {
		raw, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml"))
		if err != nil {
			t.Fatalf("read generated config: %v", err)
		}
		// Replace the whole storage: block admin init wrote (sqlite default)
		// with the backend's own. The generated template always starts
		// storage: at top level with 2-space-indented children ending
		// before the next top-level key ("secrets:") -- see
		// configs/keyorix.yaml.tpl, which admin init writes verbatim.
		text := string(raw)
		start := strings.Index(text, "storage:")
		if start < 0 {
			t.Fatalf("generated config has no storage: block:\n%s", text)
		}
		rest := text[start:]
		end := strings.Index(rest, "\nsecrets:")
		if end < 0 {
			t.Fatalf("generated config's storage: block has no following secrets: key:\n%s", text)
		}
		newText := text[:start] + backend.ConfigExtra + rest[end+1:]
		if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(newText), 0o600); err != nil { // #nosec G703 -- dir is always t.TempDir(), never attacker input; flagged only because StartServer is now exported across the harness package boundary (gosec's taint check treats exported-function string params as untrusted, unlike the identical unexported call this had before the extraction)
			t.Fatalf("rewrite config for backend %s: %v", backend.Name, err)
		}
	}

	run("encryption", "init", "--config", configPath)
	run("migrate", "--config", configPath)

	port := FreeTCPPort(t)
	RewritePort(t, dir, port)

	const bootstrapToken = "e2e-smoke-bootstrap-token-0123456789"
	// Password is deliberately unrelated to username/email/display_name --
	// internal/core/rules.DefaultPasswordPolicy rejects a password
	// containing any of those (confirmed live: "E2E-Smoke-Adm1n-Passw0rd!"
	// was rejected because it embeds the "e2e" prefix of the username
	// "e2eadmin"), same trap scripts/smoke.sh's own header comment warns
	// about for its admin password.
	s := BootAndBootstrap(t, binary, dir, env, configPath, port, bootstrapToken,
		"smoketestadmin", "smoketestadmin@example.invalid", BootstrapAdminPassword)
	s.Backend = backend
	return s
}

// RunAdminCmd runs `binary admin <args...>` in dir with env, returning its
// combined output. Shared by StartServer (fresh install) and the
// upgrade-path test's old-binary provisioning + new-binary in-place migrate.
func RunAdminCmd(binary, dir string, env []string, args ...string) (string, error) {
	cmd := exec.Command(binary, append([]string{"admin"}, args...)...) // #nosec G204 -- binary/args are this test's own fixed, non-attacker-controlled arguments nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e harness itself built or downloaded, with the harness's own fixed arguments; no external input reaches it
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// RewritePort overwrites the generated config's listen port in place --
// admin init's template always listens on 8080, which every parallel test
// leg (SQLite, Postgres, the upgrade path) needs its own free port instead
// of, to avoid colliding with each other or a real dev server.
func RewritePort(t *testing.T, dir, port string) {
	t.Helper()
	path := filepath.Join(dir, "keyorix.yaml")
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed test-tmpdir path
	if err != nil {
		t.Fatalf("read config before port rewrite: %v", err)
	}
	rewritten := portLineRe.ReplaceAllString(string(raw), fmt.Sprintf(`${1}"%s"`, port))
	if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil { // #nosec G703 -- path is derived from dir, always t.TempDir(), never attacker input; flagged only because RewritePort is now exported across the harness package boundary (gosec's taint check treats exported-function string params as untrusted, unlike the identical unexported call this had before the extraction)
		t.Fatalf("rewrite config port: %v", err)
	}
}

// StartBackgroundProcess starts s.Binary as a subprocess (cwd s.Dir, the
// given serverEnv -- which must already carry KEYORIX_CONFIG_PATH/
// KEYORIX_BOOTSTRAP_TOKEN if needed, unlike s.Env which does not), logging
// to s.LogPath, and records the running *exec.Cmd on s for Close/
// WaitHealthy to use. Does not wait for readiness -- call WaitHealthy next.
func StartBackgroundProcess(t *testing.T, s *Server, serverEnv []string) {
	t.Helper()
	logFile, err := os.Create(s.LogPath) // #nosec G304 -- fixed test-tmpdir path
	if err != nil {
		t.Fatalf("create server log: %v", err)
	}
	cmd := exec.Command(s.Binary) // #nosec G204 -- s.Binary is this test's own built/downloaded fixed path nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- runs the keyorix binary this e2e harness itself built or downloaded, with the harness's own fixed arguments; no external input reaches it
	cmd.Dir = s.Dir
	cmd.Env = serverEnv
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start keyorix-server (%s): %v", s.Backend.Name, err)
	}
	s.Cmd = cmd
}

// WaitHealthy polls s.BaseURL/health until it reports 200 or 30s elapses,
// fatally killing the process and dumping its log on timeout.
func WaitHealthy(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	healthy := false
	for time.Now().Before(deadline) {
		resp, herr := http.Get(s.BaseURL + "/health") // #nosec G107 -- fixed localhost test URL
		if herr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				healthy = true
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !healthy {
		logBytes, _ := os.ReadFile(s.LogPath)
		if s.Cmd != nil && s.Cmd.Process != nil {
			_ = s.Cmd.Process.Kill()
		}
		t.Fatalf("keyorix-server (%s) never became healthy; log:\n%s", s.Backend.Name, logBytes)
	}
}

// BootAndBootstrap starts binary as a background server (serving at
// 127.0.0.1:port, config at configPath inside dir), waits for it to become
// healthy, then claims the first admin via POST /system/init (bootstrapToken
// via header, InitSystem's preferred path). Returns the running *Server
// (caller must eventually Close it).
func BootAndBootstrap(t *testing.T, binary, dir string, env []string, configPath, port, bootstrapToken, username, email, password string) *Server {
	t.Helper()
	serverEnv := append(append([]string{}, env...),
		"KEYORIX_BOOTSTRAP_TOKEN="+bootstrapToken,
		"KEYORIX_CONFIG_PATH="+configPath,
	)
	s := &Server{
		T: t, Dir: dir, ConfigPath: configPath, BaseURL: "http://127.0.0.1:" + port,
		Binary: binary, Env: env, LogPath: filepath.Join(dir, "e2e-server-"+filepath.Base(binary)+".log"),
		Backend: DBBackend{Name: username},
	}
	StartBackgroundProcess(t, s, serverEnv)
	WaitHealthy(t, s)

	body, _ := json.Marshal(map[string]string{
		"username": username, "email": email, "password": password, "display_name": username,
	})
	req, err := http.NewRequest(http.MethodPost, s.BaseURL+"/system/init", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build /system/init request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Keyorix-Bootstrap-Token", bootstrapToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.DumpLogAndFatal("POST /system/init failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		respBody, _ := readAll(resp)
		s.DumpLogAndFatal("POST /system/init returned %d: %s", resp.StatusCode, respBody)
	}

	return s
}

// DumpLogAndFatal fails the test with msg plus the server's captured log --
// used whenever a step after boot fails and the log might explain why.
func (s *Server) DumpLogAndFatal(format string, args ...interface{}) {
	s.T.Helper()
	logBytes, _ := os.ReadFile(s.LogPath)
	msg := fmt.Sprintf(format, args...)
	s.T.Fatalf("%s\nserver log:\n%s", msg, logBytes)
}

// Close stops the server subprocess. Registered via t.Cleanup by the caller.
func (s *Server) Close() {
	if s.Cmd != nil && s.Cmd.Process != nil {
		_ = s.Cmd.Process.Kill()
		_, _ = s.Cmd.Process.Wait()
	}
}

// CLIEnv returns the environment a `keyorix` CLI invocation needs to talk to
// this running server: isolated HOME (so it never touches a real
// ~/.keyorix/cli.yaml -- see the repo's own "Local ~/.keyorix/cli.yaml breaks
// CLI tests" lesson) plus PATH.
func (s *Server) CLIEnv() []string {
	return []string{"HOME=" + s.Dir, "PATH=" + os.Getenv("PATH")}
}

func readAll(resp *http.Response) (string, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(resp.Body)
	return buf.String(), err
}
