package crypto

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- TPMKeyProvider: error-path coverage for generateAndSeal and seal ----

// errorOpener returns an opener that always fails, exercising the open-failure
// branch inside seal() — and therefore the seal-failure branch in generateAndSeal().
func errorOpener(msg string) func() (transport.TPMCloser, error) {
	return func() (transport.TPMCloser, error) {
		return nil, errors.New(msg)
	}
}

// TestTPMProvider_SealOpenFailure covers the branch in seal() where the TPM open
// call fails.  The failure propagates through generateAndSeal() on first run (no
// blob file exists) and surfaces as a "seal failed" error.
func TestTPMProvider_SealOpenFailure(t *testing.T) {
	dir := t.TempDir()
	p := NewTPMKeyProvider("", dir, "kek.tpm")
	p.open = errorOpener("tpm: open failed: device not found")

	_, err := p.KEK()
	require.Error(t, err)
	// The error should mention seal failed (from generateAndSeal) or be the raw
	// open error propagated through seal.
	assert.True(t,
		containsAny(err.Error(), "seal failed", "open failed", "device not found"),
		"unexpected error: %v", err)
}

// TestTPMProvider_UnsealOpenFailure covers the branch in unseal() where the TPM
// open call fails after a valid blob has been written.
func TestTPMProvider_UnsealOpenFailure(t *testing.T) {
	dir := t.TempDir()

	// First, seal with the simulator to produce a valid blob.
	sealer := NewTPMKeyProvider("", dir, "kek.tpm")
	sealer.open = simOpener(t, 42)
	_, err := sealer.KEK()
	require.NoError(t, err)
	require.FileExists(t, filepath.Join(dir, "kek.tpm"))

	// Now use an opener that always fails to exercise the unseal open-failure path.
	unsealer := NewTPMKeyProvider("", dir, "kek.tpm")
	unsealer.open = errorOpener("tpm: open failed")

	_, err = unsealer.KEK()
	require.Error(t, err)
}

// TestTPMProvider_GenerateAndSeal_PersistFailure exercises the SecureWriteFileSync
// error path inside generateAndSeal: the seal succeeds but the directory is
// read-only so the blob cannot be persisted.
func TestTPMProvider_GenerateAndSeal_PersistFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; read-only dir test cannot be enforced")
	}

	dir := t.TempDir()
	// Make the directory read-only after creating it so writes fail.
	require.NoError(t, os.Chmod(dir, 0500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	p := NewTPMKeyProvider("", dir, "kek.tpm")
	p.open = simOpener(t, 7)

	_, err := p.KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "persist sealed blob")
}

// TestTPMProvider_Seal_DirectCall_OpenError directly tests seal() via the
// unexported method, ensuring the open-error-returns-zero-value branch is hit.
func TestTPMProvider_Seal_DirectCall_OpenError(t *testing.T) {
	p := NewTPMKeyProvider("", "", "x.tpm")
	p.open = errorOpener("open: no device")

	_, err := p.seal([]byte("secret"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open: no device")
}

// ---- KMSKeyProvider: generateAndWrap error paths ----

// TestKMSProvider_GenerateAndWrap_PersistFailure exercises the SecureWriteFileSync
// error path inside generateAndWrap: KMS encrypt succeeds but the directory is
// read-only, so the wrapped blob cannot be written.
func TestKMSProvider_GenerateAndWrap_PersistFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; read-only dir test cannot be enforced")
	}

	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	p := NewKMSKeyProvider(&fakeKMS{tag: "k"}, "test-kms", dir, "kek.kms")
	_, err := p.KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "persist wrapped KEK")
}

// helper: reports whether s contains any of the given substrings.
func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if len(n) > 0 && len(s) >= len(n) {
			for i := 0; i <= len(s)-len(n); i++ {
				if s[i:i+len(n)] == n {
					return true
				}
			}
		}
	}
	return false
}
