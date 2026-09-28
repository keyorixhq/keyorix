//go:build e2e

// Package e2e is SESSION-I's fresh-install feature smoke driver (see
// docs/TESTING_GUIDE.md's "Fresh-install / real-backend E2E smoke" section).
// It boots a REAL keyorix-server binary (built from this checkout) against a
// freshly migrated database -- SQLite by default, PostgreSQL when
// KEYORIX_TEST_PG_DSN is set -- bootstraps an admin exactly the way a real
// operator would (admin init / admin encryption init / admin migrate / start
// / POST system/init, the same sequence scripts/smoke.sh and
// server/admin_recover_admin_integration_test.go's bootstrapAdminViaHTTP
// already use and have proven works), then drives one happy-path
// create/read/list/update/delete per feature group through the public REST
// API.
//
// WHY this exists: PR #2258 found 7 shipped features that fail with "no such
// table" on every fresh install, because no existing test exercised them
// against a database that was actually migrated from empty -- unit/handler
// tests use an in-process sqlite/mock storage seeded however the test
// author's fixture happens to seed it, not the real `admin migrate` path a
// real operator runs once. This package is the mechanism that would have
// caught that: build the real binary, migrate a real empty database, start
// the real server, and hit the real HTTP surface.
//
// Excluded from the default build (this whole package requires the `e2e`
// build tag) because it shells out to `go build`, spawns real server
// subprocesses, binds real TCP ports, and (for the PostgreSQL leg) requires
// a real Postgres instance -- unsuitable for `go test ./...`'s default fast
// inner loop. Run it explicitly: `make e2e-smoke` (see the Makefile target
// added alongside this package), or directly:
//
//	go test -tags e2e ./scripts/e2e/... -run TestAPISmoke_SQLite -v
//	KEYORIX_TEST_PG_DSN=... go test -tags e2e ./scripts/e2e/... -run TestAPISmoke_Postgres -v
package e2e

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

// repoRoot walks up from this file's own directory to find go.mod, so the
// build works regardless of how `go test` was invoked (cwd-independent, same
// approach as server/admin_integration_test.go's findServerRepoRoot).
func repoRoot(t *testing.T) string {
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
			t.Fatal("could not find repo root (go.mod) walking up from scripts/e2e")
		}
		dir = parent
	}
}

// buildBinaries compiles the real keyorix-server and keyorix (CLI) binaries
// exactly once for the whole `go test` run -- every smoke leg (SQLite,
// Postgres) exercises the identical build; paying the build cost twice would
// only slow the suite down, never change what's tested.
func buildBinaries(t *testing.T) (server, cli string) {
	t.Helper()
	buildOnce.Do(func() {
		root := repoRoot(t)
		dir, err := os.MkdirTemp("", "keyorix-e2e-bin-*")
		if err != nil {
			buildErr = fmt.Errorf("create build tmpdir: %w", err)
			return
		}

		serverPath := filepath.Join(dir, "keyorix-server")
		cmd := exec.Command("go", "build", "-o", serverPath, "./server")
		cmd.Dir = root
		if out, berr := cmd.CombinedOutput(); berr != nil {
			buildErr = fmt.Errorf("build keyorix-server: %w\n%s", berr, out)
			return
		}

		cliPath := filepath.Join(dir, "keyorix")
		cliCmd := exec.Command("go", "build", "-o", cliPath, ".")
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

// dbBackend describes which storage backend a smoke leg targets.
type dbBackend struct {
	name string // "sqlite" or "postgres", used only in test/failure output
	// configYAML is the storage: block appended to the generated config,
	// e.g. "storage:\n  type: sqlite\n  database:\n    path: keyorix.db\n"
	// for sqlite, or the postgres field-by-field form for postgres. Empty
	// means keep whatever `admin init` generated (sqlite default).
	configExtra string
	// extraEnv carries backend-specific secrets that must never land in the
	// config file (e.g. KEYORIX_DB_PASSWORD for postgres).
	extraEnv []string
	// verifyAuditFlag is the --db or --pg-dsn flag verifyAudit needs to open
	// the same database directly, without the running server's lock.
	verifyAuditFlag func(dir string) []string
}

// server is a running keyorix-server subprocess plus everything the test
// needs to talk to it and clean it up.
type server struct {
	t          *testing.T
	cmd        *exec.Cmd
	dir        string
	configPath string
	baseURL    string
	binary     string
	env        []string
	logPath    string
	backend    dbBackend
}

// freeTCPPort returns a port number no listener is bound to (same approach
// as server/admin_integration_test.go's freeTCPPort) -- avoids hardcoding a
// port that could collide with a real dev server, another test run, or the
// SQLite and Postgres legs running back to back.
func freeTCPPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free TCP port: %v", err)
	}
	defer l.Close() //nolint:errcheck
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

var portLineRe = regexp.MustCompile(`port: "8080"`)

// bootstrapAdminPassword deliberately shares no substring with the
// bootstrap admin's username/email/display_name (see startServer's
// /system/init call) -- internal/core/rules.DefaultPasswordPolicy rejects
// any password containing the account's username/email/display name.
const bootstrapAdminPassword = "Quartz-Falcon-77-Ridge!"

// smokeUserPassword is the second (non-admin) test user's password, same
// "shares no substring with username/email/display_name" constraint as
// bootstrapAdminPassword above -- that account is named "e2esmokeuser".
const smokeUserPassword = "Cobalt-Harbor-42-Ember!"

// startServer runs the exact operator-facing bootstrap sequence QUICK_START.md
// documents and scripts/smoke.sh already proves works end to end: admin init
// -> admin encryption init -> admin migrate -> start the server -> poll
// /health -> POST /system/init. Returns a *server the caller must Close().
func startServer(t *testing.T, binary string, backend dbBackend) *server {
	t.Helper()
	dir := t.TempDir()
	env := append([]string{
		"HOME=" + dir,
		"PATH=" + os.Getenv("PATH"),
		"KEYORIX_MASTER_PASSWORD=e2e-smoke-master-password-" + backend.name,
	}, backend.extraEnv...)

	configPath := "./keyorix.yaml"
	logPath := filepath.Join(dir, "e2e-server.log")

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(binary, append([]string{"admin"}, args...)...)
		cmd.Dir = dir
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("keyorix-server admin %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	run("init", "--config", configPath)

	if backend.configExtra != "" {
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
		newText := text[:start] + backend.configExtra + rest[end+1:]
		if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(newText), 0o600); err != nil {
			t.Fatalf("rewrite config for backend %s: %v", backend.name, err)
		}
	}

	run("encryption", "init", "--config", configPath)
	run("migrate", "--config", configPath)

	port := freeTCPPort(t)
	raw, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml"))
	if err != nil {
		t.Fatalf("read config before port rewrite: %v", err)
	}
	rewritten := portLineRe.ReplaceAllString(string(raw), fmt.Sprintf("port: \"%s\"", port))
	if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(rewritten), 0o600); err != nil {
		t.Fatalf("rewrite config port: %v", err)
	}

	const bootstrapToken = "e2e-smoke-bootstrap-token-0123456789"
	serverEnv := append(append([]string{}, env...),
		"KEYORIX_BOOTSTRAP_TOKEN="+bootstrapToken,
		"KEYORIX_CONFIG_PATH="+configPath,
	)

	logFile, err := os.Create(logPath) // #nosec G304 -- fixed test-tmpdir path
	if err != nil {
		t.Fatalf("create server log: %v", err)
	}
	cmd := exec.Command(binary)
	cmd.Dir = dir
	cmd.Env = serverEnv
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start keyorix-server (%s): %v", backend.name, err)
	}

	baseURL := "http://127.0.0.1:" + port
	deadline := time.Now().Add(30 * time.Second)
	healthy := false
	for time.Now().Before(deadline) {
		resp, herr := http.Get(baseURL + "/health") // #nosec G107 -- fixed localhost test URL
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
		logBytes, _ := os.ReadFile(logPath)
		_ = cmd.Process.Kill()
		t.Fatalf("keyorix-server (%s) never became healthy; log:\n%s", backend.name, logBytes)
	}

	s := &server{
		t: t, cmd: cmd, dir: dir, configPath: configPath, baseURL: baseURL,
		binary: binary, env: env, logPath: logPath, backend: backend,
	}

	// Password is deliberately unrelated to username/email/display_name --
	// internal/core/rules.DefaultPasswordPolicy rejects a password
	// containing any of those (confirmed live: "E2E-Smoke-Adm1n-Passw0rd!"
	// was rejected because it embeds the "e2e" prefix of the username
	// "e2eadmin"), same trap scripts/smoke.sh's own header comment warns
	// about for its admin password.
	body, _ := json.Marshal(map[string]string{
		"username": "smoketestadmin", "email": "smoketestadmin@example.invalid",
		"password": bootstrapAdminPassword, "display_name": "Smoke Test Administrator",
	})
	req, err := http.NewRequest(http.MethodPost, baseURL+"/system/init", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build /system/init request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Keyorix-Bootstrap-Token", bootstrapToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.dumpLogAndFatal("POST /system/init failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		respBody, _ := readAll(resp)
		s.dumpLogAndFatal("POST /system/init returned %d: %s", resp.StatusCode, respBody)
	}

	return s
}

func (s *server) dumpLogAndFatal(format string, args ...interface{}) {
	s.t.Helper()
	logBytes, _ := os.ReadFile(s.logPath)
	msg := fmt.Sprintf(format, args...)
	s.t.Fatalf("%s\nserver log:\n%s", msg, logBytes)
}

// Close stops the server subprocess. Registered via t.Cleanup by the caller.
func (s *server) Close() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_, _ = s.cmd.Process.Wait()
	}
}

func readAll(resp *http.Response) (string, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(resp.Body)
	return buf.String(), err
}
