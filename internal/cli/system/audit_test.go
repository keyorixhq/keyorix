// audit_test.go — regression coverage for #228: `keyorix system audit` used to
// hardcode config.Load("keyorix.yaml"), ignoring both --config and
// KEYORIX_CONFIG_PATH, so it silently audited a nonexistent file (and, worse,
// could report a false "✅ Audit passed" without ever validating the config the
// operator actually runs with) on any deployment where the real config isn't a
// file literally named keyorix.yaml in the current directory.
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

func captureStdout(t *testing.T, fn func()) string {
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

func resetAuditConfigFile(t *testing.T) {
	t.Helper()
	orig := auditConfigFile
	t.Cleanup(func() {
		auditConfigFile = orig
		auditCmd.Flags().Lookup("config").Changed = false
	})
}

// writeAuditableConfig writes a minimal, valid keyorix config (encryption
// enabled, with a salt/DEK path already present with correct 0600 perms/
// ownership) at dir/name — deliberately NOT named "keyorix.yaml" — so a pass
// can only happen if the audit command actually resolved and read this exact
// file rather than falling back to a hardcoded literal.
func writeAuditableConfig(t *testing.T, dir, name string) string {
	t.Helper()
	saltPath := filepath.Join(dir, "salt.bin")
	dekPath := filepath.Join(dir, "dek.bin")
	require.NoError(t, os.WriteFile(saltPath, []byte("salt"), 0600))
	require.NoError(t, os.WriteFile(dekPath, []byte("dek"), 0600))

	cfgPath := filepath.Join(dir, name)
	yaml := fmt.Sprintf("storage:\n  encryption:\n    enabled: true\n    salt_path: %s\n    dek_path: %s\n", saltPath, dekPath)
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0600))
	return cfgPath
}

// The --config flag (mirroring `system validate`) must actually be honoured:
// pointing it at a real config file with a name other than keyorix.yaml must
// make the audit read and validate THAT file.
func TestRunAudit_HonoursConfigFlagNotHardcodedKeyorixYaml(t *testing.T) {
	resetAuditConfigFile(t)
	dir := t.TempDir()
	cfgPath := writeAuditableConfig(t, dir, "production-config.yaml")

	auditConfigFile = cfgPath

	var failed bool
	out := captureStdout(t, func() {
		failed = runAuditNoExit()
	})

	assert.False(t, failed, "audit must succeed against the real config, not fail against a missing keyorix.yaml")
	assert.Contains(t, out, "Audit passed")
	assert.Contains(t, out, cfgPath, "the audited config-file path must be the one actually resolved, not a hardcoded literal")
}

// KEYORIX_CONFIG_PATH must be honoured too, matching config.Load's documented
// resolution order, when --config is left unset.
func TestRunAudit_HonoursConfigPathEnvVar(t *testing.T) {
	resetAuditConfigFile(t)
	dir := t.TempDir()
	cfgPath := writeAuditableConfig(t, dir, "env-config.yaml")

	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	auditConfigFile = "" // simulate --config left at its default (unset)

	var failed bool
	out := captureStdout(t, func() {
		failed = runAuditNoExit()
	})

	assert.False(t, failed)
	assert.Contains(t, out, "Audit passed")
	assert.Contains(t, out, cfgPath)
}

// An explicit --config still wins over KEYORIX_CONFIG_PATH, matching
// config.Load's own precedence (explicit path beats the env var).
func TestRunAudit_ConfigFlagBeatsEnvVar(t *testing.T) {
	resetAuditConfigFile(t)
	dir := t.TempDir()
	envCfg := writeAuditableConfig(t, dir, "env-config.yaml")
	flagDir := t.TempDir()
	flagCfg := writeAuditableConfig(t, flagDir, "flag-config.yaml")

	t.Setenv("KEYORIX_CONFIG_PATH", envCfg)
	auditConfigFile = flagCfg

	var failed bool
	out := captureStdout(t, func() {
		failed = runAuditNoExit()
	})

	assert.False(t, failed)
	assert.Contains(t, out, flagCfg)
	assert.NotContains(t, out, envCfg)
}

// A --config pointing at a nonexistent path must fail loudly, not silently
// report success against nothing (the exact failure mode #228 warned about).
func TestRunAudit_MissingConfigFails(t *testing.T) {
	resetAuditConfigFile(t)
	auditConfigFile = filepath.Join(t.TempDir(), "does-not-exist.yaml")

	var failed bool
	out := captureStdout(t, func() {
		failed = runAuditNoExit()
	})

	assert.True(t, failed, "a missing config file must be reported as a failure, not a false pass")
	assert.NotContains(t, out, "Audit passed")
}
