package trust

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	itrust "github.com/keyorixhq/keyorix/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeygen_WritesUsableKeypair(t *testing.T) {
	dir := t.TempDir()
	keygenPurpose, keygenKeyID, keygenDir = "update", "upd-test", dir
	require.NoError(t, keygenCmd.RunE(keygenCmd, nil))

	privPath := filepath.Join(dir, "upd-test.private.pem")
	pubPath := filepath.Join(dir, "upd-test.public.pem")
	for _, p := range []string{privPath, pubPath} {
		fi, err := os.Stat(p)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "%s must be 0600", p)
	}

	// Load the private key and sign; load the public key into a registry and verify —
	// proving the generated keypair is usable end-to-end by the trust layer.
	priv := loadPriv(t, privPath)
	pub := loadPub(t, pubPath)
	reg := itrust.NewRegistry()
	require.NoError(t, reg.Add(itrust.PurposeUpdate, "upd-test", pub))
	msg := []byte("bundle manifest")
	require.NoError(t, reg.Verify(itrust.PurposeUpdate, "upd-test", msg, ed25519.Sign(priv, msg)))
}

func TestKeygen_RefusesOverwriteWithoutForce_AllowsWithForce(t *testing.T) {
	dir := t.TempDir()
	keygenPurpose, keygenKeyID, keygenDir, keygenForce = "update", "upd-reuse", dir, false
	require.NoError(t, keygenCmd.RunE(keygenCmd, nil))

	privPath := filepath.Join(dir, "upd-reuse.private.pem")
	pubPath := filepath.Join(dir, "upd-reuse.public.pem")
	origPriv, err := os.ReadFile(privPath) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	origPub, err := os.ReadFile(pubPath) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)

	// Re-run with the same --dir/--key-id and no --force: must fail cleanly, and
	// neither file may be touched (not even the one written first on the prior run).
	err = keygenCmd.RunE(keygenCmd, nil)
	require.Error(t, err, "a re-run without --force must be refused")
	assert.Contains(t, err.Error(), "--force")

	stillPriv, err := os.ReadFile(privPath) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	stillPub, err := os.ReadFile(pubPath) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	assert.Equal(t, origPriv, stillPriv, "private key must be untouched by the rejected re-run")
	assert.Equal(t, origPub, stillPub, "public key must be untouched by the rejected re-run")

	// With --force, the overwrite proceeds and produces a fresh (different) keypair.
	keygenForce = true
	t.Cleanup(func() { keygenForce = false })
	require.NoError(t, keygenCmd.RunE(keygenCmd, nil), "--force must allow the overwrite")

	newPriv, err := os.ReadFile(privPath) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	newPub, err := os.ReadFile(pubPath) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	assert.NotEqual(t, origPriv, newPriv, "--force must actually overwrite the private key")
	assert.NotEqual(t, origPub, newPub, "--force must actually overwrite the public key")
}

// #265: a dangling symlink planted at the target path (its target not yet existing,
// so the pre-write os.Stat existence check doesn't catch it) must not be silently
// written through — the write should fail rather than create the key material at
// the symlink's target location outside keygenDir.
func TestKeygen_RefusesToFollowSymlinkAtTarget(t *testing.T) {
	dir := t.TempDir()
	outsideTarget := filepath.Join(t.TempDir(), "exfiltrated.private.pem")
	require.NoError(t, os.Symlink(outsideTarget, filepath.Join(dir, "sym-test.private.pem")))

	keygenPurpose, keygenKeyID, keygenDir, keygenForce = "update", "sym-test", dir, false
	err := keygenCmd.RunE(keygenCmd, nil)
	require.Error(t, err, "writing through a pre-planted symlink must be refused")

	_, statErr := os.Stat(outsideTarget)
	assert.True(t, os.IsNotExist(statErr), "the symlink target must NOT have been created")
}

func TestKeygen_RejectsBadPurposeAndMissingKeyID(t *testing.T) {
	keygenPurpose, keygenKeyID, keygenDir = "bogus", "x", t.TempDir()
	require.Error(t, keygenCmd.RunE(keygenCmd, nil), "an invalid purpose is rejected")

	keygenPurpose, keygenKeyID = "update", ""
	require.Error(t, keygenCmd.RunE(keygenCmd, nil), "a missing key-id is rejected")
}

func loadPriv(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	require.NotNil(t, block)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	return key.(ed25519.PrivateKey)
}

func loadPub(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	require.NotNil(t, block)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	return key.(ed25519.PublicKey)
}
