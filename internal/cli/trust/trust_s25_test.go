package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetKeygenVars restores all package-level keygen flag variables to safe
// defaults after each test so that parallel / sequential test runs don't
// bleed state.
func resetKeygenVars(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		keygenPurpose = ""
		keygenKeyID = ""
		keygenDir = "."
		keygenForce = false
	})
}

// TestKeygen_InvalidPurpose checks that an unrecognised --purpose value is
// rejected with a message that mentions both valid choices.
func TestKeygen_InvalidPurpose(t *testing.T) {
	resetKeygenVars(t)
	keygenPurpose = "invalid"
	keygenKeyID = "some-key"
	keygenDir = t.TempDir()

	err := keygenCmd.RunE(keygenCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--purpose must be")
}

// TestKeygen_EmptyKeyID checks that an empty --key-id is rejected.
func TestKeygen_EmptyKeyID(t *testing.T) {
	resetKeygenVars(t)
	keygenPurpose = "update"
	keygenKeyID = "   " // whitespace-only → trimmed to ""
	keygenDir = t.TempDir()

	err := keygenCmd.RunE(keygenCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--key-id is required")
}

// TestKeygen_FileAlreadyExists_RefusesWithoutForce verifies that when privPath
// already exists and keygenForce is false the command returns an "already
// exists — refusing" error without touching either file.
func TestKeygen_FileAlreadyExists_RefusesWithoutForce(t *testing.T) {
	resetKeygenVars(t)
	dir := t.TempDir()
	keygenPurpose = "update"
	keygenKeyID = "exist-key"
	keygenDir = dir
	keygenForce = false

	// Pre-create the private-key path so the existence check triggers.
	privPath := filepath.Join(dir, "exist-key.private.pem")
	require.NoError(t, os.WriteFile(privPath, []byte("dummy"), 0o600))

	err := keygenCmd.RunE(keygenCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
	assert.Contains(t, err.Error(), "--force")
}

// TestKeygen_StatNonNotExistError covers the branch where os.Stat on a
// candidate path returns an error that is NOT os.IsNotExist — for example
// EACCES when the parent directory is not searchable.  The command must
// surface the "check <path>: …" error.
func TestKeygen_StatNonNotExistError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("cannot test permission errors when running as root")
	}

	resetKeygenVars(t)
	dir := t.TempDir()

	// Make the directory non-searchable so that os.Stat on any path inside it
	// returns EACCES (not ENOENT).
	require.NoError(t, os.Chmod(dir, 0o000))
	t.Cleanup(func() {
		// Restore so t.TempDir's own cleanup can remove the directory.
		_ = os.Chmod(dir, 0o700)
	})

	keygenPurpose = "update"
	keygenKeyID = "perm-key"
	keygenDir = dir
	keygenForce = false

	err := keygenCmd.RunE(keygenCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "check ")
}

// TestKeygen_LicensePurpose verifies the success path when purpose is
// "license", which sets ldVar = "licenseKeysB64" and writes both PEM files.
func TestKeygen_LicensePurpose(t *testing.T) {
	resetKeygenVars(t)
	dir := t.TempDir()
	keygenPurpose = "license"
	keygenKeyID = "lic-2026"
	keygenDir = dir

	require.NoError(t, keygenCmd.RunE(keygenCmd, nil))

	privPath := filepath.Join(dir, "lic-2026.private.pem")
	pubPath := filepath.Join(dir, "lic-2026.public.pem")
	for _, p := range []string{privPath, pubPath} {
		fi, err := os.Stat(p)
		require.NoError(t, err, "expected file to exist: %s", p)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "%s must be 0600", p)
	}

	// The private PEM content must carry "licenseKeysB64" nowhere (that string
	// appears only in the printed ldflags snippet, not in the key files) — but
	// we can confirm the files are valid PEM.
	raw, err := os.ReadFile(privPath) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(raw), "-----BEGIN"), "private key must be PEM-encoded")

	pub, err := os.ReadFile(pubPath) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(pub), "-----BEGIN"), "public key must be PEM-encoded")
}

// TestKeygen_ForceOverwritesExistingFiles verifies that --force causes a fresh
// keypair to be generated even when both PEM files already exist, and that the
// resulting files differ from the originals (i.e. the overwrite actually ran).
func TestKeygen_ForceOverwritesExistingFiles(t *testing.T) {
	resetKeygenVars(t)
	dir := t.TempDir()
	keygenPurpose = "update"
	keygenKeyID = "force-key"
	keygenDir = dir

	// First run: generate the initial keypair.
	require.NoError(t, keygenCmd.RunE(keygenCmd, nil))

	privPath := filepath.Join(dir, "force-key.private.pem")
	pubPath := filepath.Join(dir, "force-key.public.pem")
	origPriv, err := os.ReadFile(privPath) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	origPub, err := os.ReadFile(pubPath) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)

	// Second run with --force: must succeed and produce a new keypair.
	keygenForce = true
	require.NoError(t, keygenCmd.RunE(keygenCmd, nil))

	newPriv, err := os.ReadFile(privPath) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	newPub, err := os.ReadFile(pubPath) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)

	assert.NotEqual(t, origPriv, newPriv, "private key must be regenerated under --force")
	assert.NotEqual(t, origPub, newPub, "public key must be regenerated under --force")
}

// TestKeygen_DirDoesNotExist verifies that when keygenDir names a
// non-existent directory the write step fails and the error is wrapped as
// "write private key: …".
func TestKeygen_DirDoesNotExist(t *testing.T) {
	resetKeygenVars(t)
	keygenPurpose = "update"
	keygenKeyID = "nodir-key"
	keygenDir = filepath.Join(t.TempDir(), "nonexistent", "subdir")
	keygenForce = false

	err := keygenCmd.RunE(keygenCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write private key")
}

// TestKeygen_PublicKeyWriteFails_AfterPrivateKeySucceeds covers the branch
// where the private key write succeeds but the public key write fails: a
// dangling symlink planted only at the public-key path makes
// SecureWriteFileSync refuse to write through it (O_NOFOLLOW), while the
// private-key path is untouched and writes normally. The error must be
// wrapped as "write public key: …", and the already-written private key
// file must be left in place (the command does not roll it back).
func TestKeygen_PublicKeyWriteFails_AfterPrivateKeySucceeds(t *testing.T) {
	resetKeygenVars(t)
	dir := t.TempDir()
	outsideTarget := filepath.Join(t.TempDir(), "exfiltrated.public.pem")
	require.NoError(t, os.Symlink(outsideTarget, filepath.Join(dir, "pub-sym-key.public.pem")))

	keygenPurpose = "update"
	keygenKeyID = "pub-sym-key"
	keygenDir = dir
	keygenForce = false

	err := keygenCmd.RunE(keygenCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write public key")

	_, statErr := os.Stat(outsideTarget)
	assert.True(t, os.IsNotExist(statErr), "the symlink target must NOT have been created")

	privPath := filepath.Join(dir, "pub-sym-key.private.pem")
	fi, err := os.Stat(privPath)
	require.NoError(t, err, "the private key write happens first and must have succeeded")
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}
