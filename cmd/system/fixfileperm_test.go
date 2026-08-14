// fixfileperm_test.go — regression coverage for #G59: `keyorix system
// fixfileperm` hardcoded config.Load("keyorix.yaml"), ignoring both --config
// and KEYORIX_CONFIG_PATH (unlike its sibling `system audit`), and fed
// config-driven salt/DEK/config paths straight to FixFilePerms's autofix
// (chmod) with no containment validation (unlike internal/startup/
// validation.go's SafeFilePermPath) — so a config-driven ".." path traversal
// in dek_path could make autofix chmod an arbitrary file outside the intended
// key directory.
package system

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureFixFilePermStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func resetFixFilePermConfigFile(t *testing.T) {
	t.Helper()
	orig := fixFilePermConfigFile
	t.Cleanup(func() {
		fixFilePermConfigFile = orig
		FixFilePermCmd.Flags().Lookup("config").Changed = false
	})
}

// writeFixFilePermConfig writes a minimal, valid keyorix config (encryption
// enabled, salt/DEK paths already present with correct perms) at dir/name —
// deliberately NOT named "keyorix.yaml" — so success can only happen if the
// command actually resolved and read this exact file.
func writeFixFilePermConfig(t *testing.T, dir, name, saltPath, dekPath string) string {
	t.Helper()
	require.NoError(t, os.WriteFile(saltPath, []byte("salt"), 0600))
	require.NoError(t, os.WriteFile(dekPath, []byte("dek"), 0600))

	cfgPath := filepath.Join(dir, name)
	yaml := fmt.Sprintf("storage:\n  encryption:\n    enabled: true\n    salt_path: %s\n    dek_path: %s\n", saltPath, dekPath)
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0600))
	return cfgPath
}

// The --config flag (mirroring `system audit`) must actually be honoured:
// pointing it at a real config file with a name other than keyorix.yaml must
// make the fix operate on THAT file's salt/DEK/config paths.
func TestRunFixFilePerm_HonoursConfigFlagNotHardcodedKeyorixYaml(t *testing.T) {
	resetFixFilePermConfigFile(t)
	dir := t.TempDir()
	cfgPath := writeFixFilePermConfig(t, dir, "production-config.yaml",
		filepath.Join(dir, "salt.bin"), filepath.Join(dir, "dek.bin"))
	// Deliberately loosen the config file's own perms so the fix must actually
	// touch it — otherwise a no-op pass wouldn't distinguish "fixed the right
	// file" from "silently did nothing to a nonexistent keyorix.yaml".
	require.NoError(t, os.Chmod(cfgPath, 0644))

	fixFilePermConfigFile = cfgPath

	var out string
	assert.NotPanics(t, func() {
		out = captureFixFilePermStdout(t, func() { runFixFilePermNoExit() })
	})
	assert.Contains(t, out, "fixed successfully")

	info, err := os.Stat(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "the resolved config file's own perms must have been fixed")
}

// KEYORIX_CONFIG_PATH must be honoured too, matching config.Load's documented
// resolution order, when --config is left unset — same property as audit.go's
// TestRunAudit_HonoursConfigPathEnvVar.
func TestRunFixFilePerm_HonoursConfigPathEnvVar(t *testing.T) {
	resetFixFilePermConfigFile(t)
	dir := t.TempDir()
	cfgPath := writeFixFilePermConfig(t, dir, "env-config.yaml",
		filepath.Join(dir, "salt.bin"), filepath.Join(dir, "dek.bin"))

	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	fixFilePermConfigFile = "" // simulate --config left at its default (unset)

	out := captureFixFilePermStdout(t, func() { runFixFilePermNoExit() })
	assert.Contains(t, out, "fixed successfully")
}

// A ".."-traversal DEK path must be refused rather than handed to
// FixFilePerms's autofix (chmod) — the exact #G59 containment gap.
func TestRunFixFilePerm_RefusesPathTraversalInDEKPath(t *testing.T) {
	resetFixFilePermConfigFile(t)
	dir := t.TempDir()
	saltPath := filepath.Join(dir, "salt.bin")
	require.NoError(t, os.WriteFile(saltPath, []byte("salt"), 0600))

	// A RELATIVE traversal with more ".." segments than leading real ones — the
	// exact shape SafeFilePermPath's own established test suite
	// (TestSafeFilePermPath_RejectsTraversal) validates: filepath.Clean cannot
	// fully resolve it away, so it still contains ".." after cleaning.
	const traversalDEKPath = "sub/../../outside/dek.key"
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	yaml := fmt.Sprintf("storage:\n  encryption:\n    enabled: true\n    salt_path: %s\n    dek_path: %s\n", saltPath, traversalDEKPath)
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0600))
	// The config file itself starts at a safe 0600 — a bypassed traversal check
	// would otherwise still leave THIS file looking "fixed" and mask the gap.
	require.NoError(t, os.Chmod(saltPath, 0644))

	fixFilePermConfigFile = cfgPath

	var failed bool
	out := captureFixFilePermStdout(t, func() { failed = runFixFilePermNoExit() })

	assert.True(t, failed, "a '..'-traversal dek_path must be refused, not silently chmod'd")
	assert.Contains(t, out, "unsafe")
}

// A --config pointing at a nonexistent path must fail loudly, not silently
// report success against nothing.
func TestRunFixFilePerm_MissingConfigFails(t *testing.T) {
	resetFixFilePermConfigFile(t)
	fixFilePermConfigFile = filepath.Join(t.TempDir(), "does-not-exist.yaml")

	var failed bool
	out := captureFixFilePermStdout(t, func() { failed = runFixFilePermNoExit() })

	assert.True(t, failed, "a missing config file must be reported as a failure, not a false pass")
	assert.NotContains(t, out, "fixed successfully")
}
