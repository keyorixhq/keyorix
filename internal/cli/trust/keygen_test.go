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
