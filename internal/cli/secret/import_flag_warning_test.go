// import_flag_warning_test.go — #G58: 'secret import' must warn on stderr when
// --vault-token is passed on the command line (ps/proc + shell-history exposure,
// same property already covered for --value in value_flag_warning_test.go), and
// its --dry-run preview must never print a substring of the real secret value.
package secret

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunImport_VaultTokenFlagWarnsOnCommandLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "in.env")
	require.NoError(t, os.WriteFile(path, []byte("FOO=bar\n"), 0o600))

	origFile, origFormat, origDryRun, origToken := importFile, importFormat, importDryRun, vaultToken
	t.Cleanup(func() {
		importFile, importFormat, importDryRun, vaultToken = origFile, origFormat, origDryRun, origToken
		importCmd.Flags().Lookup("vault-token").Changed = false
	})
	importFile = path
	importFormat = "dotenv"
	importDryRun = true
	require.NoError(t, importCmd.Flags().Set("vault-token", "s3cr3t-vault-token-on-argv"))

	out := captureStderr(t, func() {
		_ = runImport(importCmd, nil)
	})
	assert.Contains(t, out, "--vault-token")
	assert.Contains(t, out, "ps/proc")
}

func TestRunImport_DryRunPreviewNeverContainsRealValueSubstring(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "in.env")
	const secretValue = "sup3r-s3cr3t-database-password-xyz"
	require.NoError(t, os.WriteFile(path, []byte("DB_PASSWORD="+secretValue+"\n"), 0o600))

	origFile, origFormat, origDryRun := importFile, importFormat, importDryRun
	t.Cleanup(func() { importFile, importFormat, importDryRun = origFile, origFormat, origDryRun })
	importFile = path
	importFormat = "dotenv"
	importDryRun = true

	out := captureStdout(t, func() {
		_ = runImport(importCmd, nil)
	})
	assert.Contains(t, out, "DB_PASSWORD")
	// The whole value, and any 8+ char substring of it, must never appear —
	// this is the review's own detection_idea for G58.
	assert.NotContains(t, out, secretValue)
	for i := 0; i+8 <= len(secretValue); i += 4 {
		assert.NotContains(t, out, secretValue[i:i+8])
	}
}
