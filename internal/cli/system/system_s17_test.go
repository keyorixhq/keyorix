// system_s17_test.go — coverage sprint 17 for internal/cli/system.
// Targets:
//   - runAudit (50%): the success path that does NOT call os.Exit, and the
//     cobra Run wrapper (auditCmd.Run)
//   - runAuditNoExit (83.3%): the FixFilePerms failure branch (wrong permissions)
package system

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeAuditableConfigWrongPerms is like writeAuditableConfig but writes the
// config file with 0644 instead of 0600, so FixFilePerms will report a
// permissions mismatch and return an error (audit fails).
func writeAuditableConfigWrongPerms(t *testing.T, dir, name string) string {
	t.Helper()
	saltPath := filepath.Join(dir, "salt.bin")
	dekPath := filepath.Join(dir, "dek.bin")
	require.NoError(t, os.WriteFile(saltPath, []byte("salt"), 0600))
	require.NoError(t, os.WriteFile(dekPath, []byte("dek"), 0600))

	cfgPath := filepath.Join(dir, name)
	yaml := fmt.Sprintf("storage:\n  encryption:\n    enabled: true\n    salt_path: %s\n    dek_path: %s\n", saltPath, dekPath)
	// Wrong mode: 0644 instead of 0600 — FixFilePerms will flag this.
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0644))
	return cfgPath
}

// TestRunAudit_SuccessDoesNotCallExit exercises the happy path of runAudit:
// when runAuditNoExit() returns false, runAudit must return without calling
// os.Exit. We call runAudit() directly with a valid config so the function
// completes normally and the test process stays alive.
func TestRunAudit_SuccessDoesNotCallExit(t *testing.T) {
	resetAuditConfigFile(t)
	dir := t.TempDir()
	cfgPath := writeAuditableConfig(t, dir, "run-audit-ok.yaml")

	auditConfigFile = cfgPath

	// If runAudit() called os.Exit the test binary would die; reaching this
	// assertion confirms it did NOT.
	out := captureStdout(t, func() {
		runAudit()
	})
	assert.Contains(t, out, "Audit passed")
}

// TestAuditCmd_Run exercises the cobra command's Run closure (line 16-18 of
// audit.go), which simply calls runAudit(). We point auditConfigFile at a
// known-good config so runAudit() succeeds and does not os.Exit.
func TestAuditCmd_Run(t *testing.T) {
	resetAuditConfigFile(t)
	dir := t.TempDir()
	cfgPath := writeAuditableConfig(t, dir, "audit-cmd-run.yaml")

	auditConfigFile = cfgPath

	out := captureStdout(t, func() {
		auditCmd.Run(auditCmd, nil)
	})
	assert.Contains(t, out, "Audit passed")
}

// TestRunAuditNoExit_BadPermsFails exercises the FixFilePerms failure branch
// (lines 62-64 of audit.go): when the config file has wrong permissions (0644
// instead of 0600), FixFilePerms returns an error in audit-only mode and
// runAuditNoExit must return true.
func TestRunAuditNoExit_BadPermsFails(t *testing.T) {
	resetAuditConfigFile(t)
	dir := t.TempDir()
	cfgPath := writeAuditableConfigWrongPerms(t, dir, "bad-perms.yaml")

	auditConfigFile = cfgPath

	var failed bool
	out := captureStdout(t, func() {
		failed = runAuditNoExit()
	})

	assert.True(t, failed, "audit must fail when a file has wrong permissions")
	assert.NotContains(t, out, "Audit passed")
}

// TestRunAudit_ExitOnFailure verifies that runAudit() calls os.Exit(1) when
// the audit fails. We run it in a subprocess so the os.Exit does not kill the
// test binary.
func TestRunAudit_ExitOnFailure(t *testing.T) {
	if os.Getenv("AUDIT_EXIT_SUBPROCESS") == "1" {
		// This is the subprocess. Run the audit against a missing config so it
		// fails and triggers os.Exit(1).
		auditConfigFile = filepath.Join(t.TempDir(), "does-not-exist.yaml")
		runAudit()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRunAudit_ExitOnFailure")
	cmd.Env = append(os.Environ(), "AUDIT_EXIT_SUBPROCESS=1")
	err := cmd.Run()

	// exec.Command.Run returns a non-nil error when the subprocess exits with a
	// non-zero status (os.Exit(1) produces exit status 1).
	require.Error(t, err, "subprocess must exit non-zero when the audit fails")
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitCode())
}
