package main

// admin_integration_test.go exercises `keyorix-server admin <cmd>` as a real
// subprocess against the built binary (ADR-108 §B, PR 11) -- the same
// build-then-exec pattern internal/cli/cli_remote_mode_behavior_test.go uses
// for the CLI binary. Covers: plain `keyorix-server` flag parsing/behavior
// stays unchanged; each admin command against a temp SQLite database; the
// running-server guard refuses without --force; `admin diagnose` names the
// failing check for a broken config, a missing KEK, and an unmigrated
// database. Postgres-backed admin-command coverage lives in
// admin_integration_postgres_test.go (gated on KEYORIX_TEST_PG_DSN).

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/serverguard"
)

var (
	sharedServerBinOnce sync.Once
	sharedServerBinPath string
	sharedServerBinErr  error
)

// buildServerBinary compiles the real keyorix-server binary once for the
// whole test binary run (not once per test function -- every subprocess
// test in this file exercises the identical build, and `go build ./server`
// alone takes several seconds; paying that N times across a dozen tests
// dominated this suite's wall-clock for no benefit).
func buildServerBinary(t *testing.T) string {
	t.Helper()
	sharedServerBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "keyorix-server-admin-test-bin-*")
		if err != nil {
			sharedServerBinErr = err
			return
		}
		binPath := filepath.Join(dir, "keyorix-server")
		repoRoot := findServerRepoRoot(t)
		cmd := exec.Command("go", "build", "-o", binPath, "./server")
		cmd.Dir = repoRoot
		if out, err := cmd.CombinedOutput(); err != nil {
			sharedServerBinErr = fmt.Errorf("failed to build keyorix-server binary: %w\n%s", err, out)
			return
		}
		sharedServerBinPath = binPath
	})
	if sharedServerBinErr != nil {
		t.Fatalf("%v", sharedServerBinErr)
	}
	return sharedServerBinPath
}

// findServerRepoRoot walks up from the current working directory (server/)
// to the directory containing go.mod, since `go build ./server` must run
// from the module root.
func findServerRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod) walking up from server/")
		}
		dir = parent
	}
}

func runAdmin(t *testing.T, binPath, dir string, env []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(binPath, append([]string{"admin"}, args...)...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// adminConfigForProbe loads a config file the same way admin commands do,
// for tests that need to call internal/serverguard.ProbeRunning directly
// in-process (see waitForPresence).
func adminConfigForProbe(path string) (*config.Config, error) {
	return config.Load(path)
}

// waitForPresence polls internal/serverguard.ProbeRunning in-process until
// it reports a live server (or the timeout elapses). See
// TestAdminGuard_RefusesWhileServerRunning_ThenForceOverrides's inline
// comment for why polling must go through ProbeRunning directly rather than
// shelling out to an admin command that could itself race the server's own
// boot-time lock acquisitions.
func waitForPresence(t *testing.T, cfg *config.Config, timeoutSeconds int) bool {
	t.Helper()
	deadline := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
	for time.Now().Before(deadline) {
		running, _, err := serverguard.ProbeRunning(cfg)
		if err != nil {
			t.Fatalf("ProbeRunning: %v", err)
		}
		if running {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func baseEnv(dir string) []string {
	return []string{
		"HOME=" + dir,
		"PATH=/usr/bin:/bin",
	}
}

// --- Plain server flag parsing/behavior stays unchanged ---------------------

func TestPlainServer_PassphraseFlagsStillParse(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()

	// No config file present: the plain server must reach config loading and
	// fail there -- NOT fail on flag parsing (which would mean the admin
	// dispatch broke the existing -passphrase-* flag set).
	cmd := exec.Command(bin, "-passphrase-stdin")
	cmd.Dir = dir
	cmd.Env = baseEnv(dir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected the plain server to fail (no config present), got success:\n%s", out)
	}
	if strings.Contains(string(out), "flag provided but not defined") {
		t.Fatalf("admin dispatch broke plain-server flag parsing: %s", out)
	}
	if strings.Contains(string(out), "not defined: -passphrase-stdin") {
		t.Fatalf("passphrase-stdin flag no longer recognized: %s", out)
	}
}

func TestPlainServer_HelpUsageUnchanged(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	cmd := exec.Command(bin, "-h")
	cmd.Dir = dir
	cmd.Env = baseEnv(dir)
	out, _ := cmd.CombinedOutput()
	for _, want := range []string{"-passphrase-fd", "-passphrase-file", "-passphrase-stdin"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("expected plain server -h usage to mention %q, got:\n%s", want, out)
		}
	}
	// The stdlib flag package's usage output has no concept of subcommands at
	// all -- it is exactly the flag list above, nothing else. Checking for
	// "Available Commands:" (cobra's own section heading, used by `admin
	// --help`) is more precise than a bare "admin" substring, which
	// false-positives on the binary's own temp path
	// (buildServerBinary names it .../keyorix-server-admin-test-bin-*/...).
	if strings.Contains(string(out), "Available Commands:") {
		t.Errorf("plain server -h usage should not look like the cobra-based admin command tree:\n%s", out)
	}
}

func TestAdminDispatch_DoesNotStartAListener(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	out, err := runAdmin(t, bin, dir, baseEnv(dir), "--help")
	if err != nil {
		t.Fatalf("admin --help failed: %v\n%s", err, out)
	}
	for _, want := range []string{"init", "validate", "audit", "diagnose", "migrate"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected admin --help to list %q, got:\n%s", want, out)
		}
	}
}

// --- Full admin workflow against a temp SQLite database ---------------------

func TestAdminWorkflow_SQLite(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-sqlite")

	out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "keyorix.yaml")); statErr != nil {
		t.Fatalf("expected config file to be created: %v", statErr)
	}

	// First diagnose creates the DEK (first-boot key derivation) and must
	// report every check passing.
	out, err = runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin diagnose failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		"[ OK ] config parse",
		"[ OK ] KEK/passphrase access",
		"[ OK ] database open",
		"[ OK ] migration state",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected diagnose output to contain %q, got:\n%s", want, out)
		}
	}

	out, err = runAdmin(t, bin, dir, env, "validate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin validate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "All validations passed") {
		t.Errorf("expected validate to pass after init+diagnose, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "audit", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin audit failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Audit passed") {
		t.Errorf("expected audit to pass, got:\n%s", out)
	}

	out, err = runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "migrated successfully") {
		t.Errorf("expected migrate to report success, got:\n%s", out)
	}

	// migrate must be idempotent -- re-running against an already-migrated DB
	// must still succeed.
	out, err = runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("second admin migrate (idempotency check) failed: %v\n%s", err, out)
	}
}

// --- diagnose names the failing check ---------------------------------------

func TestAdminDiagnose_BrokenConfig(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte("not: [valid yaml"), 0600); err != nil {
		t.Fatalf("write broken config: %v", err)
	}
	out, err := runAdmin(t, bin, dir, baseEnv(dir), "diagnose", "--config", "./keyorix.yaml")
	if err == nil {
		t.Fatalf("expected diagnose to fail against a broken config, got success:\n%s", out)
	}
	if !strings.Contains(out, "[FAIL] config parse") {
		t.Errorf("expected diagnose to name 'config parse' as the failing check, got:\n%s", out)
	}
}

func TestAdminDiagnose_MissingKEK(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := baseEnv(dir) // deliberately no KEYORIX_MASTER_PASSWORD

	out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}

	out, err = runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml")
	if err == nil {
		t.Fatalf("expected diagnose to fail with no passphrase available, got success:\n%s", out)
	}
	if !strings.Contains(out, "[ OK ] config parse") {
		t.Errorf("expected config parse to pass before the KEK check, got:\n%s", out)
	}
	if !strings.Contains(out, "[FAIL] KEK/passphrase access") {
		t.Errorf("expected diagnose to name 'KEK/passphrase access' as the failing check, got:\n%s", out)
	}
}

func TestAdminDiagnose_UnmigratedDatabase(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-unmigrated")

	out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}

	// Derive the KEK without ever opening storage through the migrating
	// factory: init's own audit-event recording (recordAdminAction) DOES
	// open (and thus migrate) storage as a side effect, so use --config only
	// through diagnose's encryption check in isolation is not enough to
	// avoid it. Delete the database file init created and replace it with an
	// empty, definitely-unmigrated one to force the "no tables yet" state
	// diagnose's migration-state check reports.
	dbPath := filepath.Join(dir, "keyorix.db")
	if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove db: %v", err)
	}
	if err := os.WriteFile(dbPath, nil, 0600); err != nil {
		t.Fatalf("recreate empty db: %v", err)
	}

	out, err = runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml")
	if err != nil {
		t.Fatalf("expected diagnose to succeed (an unmigrated DB is a WARN, not a FAIL): %v\n%s", err, out)
	}
	if !strings.Contains(out, "[WARN] migration state") {
		t.Errorf("expected diagnose to WARN on an unmigrated database, got:\n%s", out)
	}
	if !strings.Contains(out, "admin migrate") {
		t.Errorf("expected diagnose to point at `admin migrate`, got:\n%s", out)
	}
}

// --- running-server guard ----------------------------------------------------

func TestAdminGuard_RefusesWhileServerRunning_ThenForceOverrides(t *testing.T) {
	bin := buildServerBinary(t)
	dir := t.TempDir()
	env := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-guard")

	if out, err := runAdmin(t, bin, dir, env, "init", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin init failed: %v\n%s", err, out)
	}
	// diagnose performs first-boot KEK derivation (creates keys/kek.salt and
	// keys/dek.key) -- required before the real server below can pass its own
	// startup validation and actually boot far enough to acquire the
	// presence lock this test is probing for.
	if out, err := runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin diagnose (key derivation) failed: %v\n%s", err, out)
	}
	if out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml"); err != nil {
		t.Fatalf("admin migrate failed: %v\n%s", err, out)
	}

	serverEnv := append(baseEnv(dir), "KEYORIX_MASTER_PASSWORD=test-passphrase-guard", "KEYORIX_CONFIG_PATH=./keyorix.yaml")
	serverCmd := exec.Command(bin)
	serverCmd.Dir = dir
	serverCmd.Env = serverEnv
	logFile, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		t.Fatalf("create server log: %v", err)
	}
	defer logFile.Close() //nolint:errcheck
	serverCmd.Stdout = logFile
	serverCmd.Stderr = logFile
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		_ = serverCmd.Process.Kill()
		_, _ = serverCmd.Process.Wait()
	})

	// Poll internal/serverguard.ProbeRunning DIRECTLY (in-process, no
	// subprocess) rather than shelling out to an admin command: any admin
	// command that itself touches the pre-existing migration lock
	// (withMigrationLock, internal/storage/factory.go) or the DEK exclusive
	// lock (internal/encryption/exclusive_lock.go) during the polling window
	// races the SERVER's own boot-time acquisition of those SAME locks --
	// and since both are non-blocking, whichever side loses hard-fails
	// instead of waiting, which can kill the server this test is trying to
	// observe. ProbeRunning touches only the NEW presence lock this task
	// adds, so it cannot collide with either pre-existing lock.
	probeCfg, err := adminConfigForProbe(filepath.Join(dir, "keyorix.yaml"))
	if err != nil {
		t.Fatalf("load config for probe: %v", err)
	}
	if !waitForPresence(t, probeCfg, 30) {
		logBytes, _ := os.ReadFile(filepath.Join(dir, "server.log"))
		t.Fatalf("expected the server to acquire the presence lock within the deadline; server log:\n%s", logBytes)
	}

	out, err := runAdmin(t, bin, dir, env, "migrate", "--config", "./keyorix.yaml")
	if err == nil || !strings.Contains(out, "admin commands must not run concurrently") {
		logBytes, _ := os.ReadFile(filepath.Join(dir, "server.log"))
		t.Fatalf("expected admin migrate to refuse while the server is running, got (err=%v):\n%s\nserver log:\n%s", err, out, logBytes)
	}

	// --force must reach past the guard (and then legitimately hit the
	// pre-existing, unrelated DEK exclusive lock the live server also
	// holds -- confirming --force bypasses ONLY this guard, not every
	// safety mechanism in the codebase).
	out, err = runAdmin(t, bin, dir, env, "diagnose", "--config", "./keyorix.yaml", "--force")
	if err == nil {
		t.Fatalf("expected --force to still fail (DEK lock genuinely held by the live server), got success:\n%s", out)
	}
	if strings.Contains(out, "admin commands must not run concurrently") {
		t.Errorf("--force should have bypassed the server-presence guard entirely, got:\n%s", out)
	}
}
