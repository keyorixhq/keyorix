package crypto

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// closableTPM adapts a simulator's io.ReadWriteCloser to a transport.TPMCloser.
type closableTPM struct {
	transport.TPM
	io.Closer
}

// simOpener returns an opener that yields a simulator with a FIXED seed, so the
// primary key (derived from the seed) is identical across separate opens — exactly
// as a real hardware TPM reproduces its primary across restarts. This lets a blob
// sealed on one open be unsealed on a later one (the persist-then-restart flow).
func simOpener(t *testing.T, seed int64) func() (transport.TPMCloser, error) {
	t.Helper()
	return func() (transport.TPMCloser, error) {
		sim, err := simulator.GetWithFixedSeedInsecure(seed)
		if err != nil {
			return nil, err
		}
		return closableTPM{TPM: transport.FromReadWriter(sim), Closer: sim}, nil
	}
}

func newTPMProvider(t *testing.T, baseDir string, seed int64) *TPMKeyProvider {
	t.Helper()
	p := NewTPMKeyProvider("", baseDir, "kek.tpm")
	p.open = simOpener(t, seed)
	return p
}

func TestTPMKeyProvider_Name(t *testing.T) {
	assert.Equal(t, "tpm", NewTPMKeyProvider("", "", "x").Name())
}

func TestTPMKeyProvider_SealsThenUnsealsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()

	// First call: no blob yet → generate + seal + persist; returns a 32-byte KEK.
	kek1, err := newTPMProvider(t, dir, 99).KEK()
	require.NoError(t, err)
	require.Len(t, kek1, KEKSize)
	require.FileExists(t, filepath.Join(dir, "kek.tpm"))

	// A fresh provider over the same blob + same (simulated) TPM unseals the identical
	// KEK — the persist-then-restart path.
	kek2, err := newTPMProvider(t, dir, 99).KEK()
	require.NoError(t, err)
	assert.Equal(t, kek1, kek2, "the same TPM must unseal the identical KEK across restarts")
}

func TestTPMKeyProvider_DifferentTPMCannotUnseal(t *testing.T) {
	dir := t.TempDir()

	_, err := newTPMProvider(t, dir, 1).KEK() // seal under TPM seed 1
	require.NoError(t, err)

	// A different TPM (different seed → different primary) must NOT unseal the blob —
	// the KEK is bound to the sealing hardware.
	_, err = newTPMProvider(t, dir, 2).KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unseal failed")
	// No PCR policy is enforced (see the package doc), so the error must not suggest a
	// PCR mismatch was the cause — that would misleadingly imply boot-state binding
	// this provider does not actually do.
	assert.NotContains(t, err.Error(), "PCR", "the error must not imply PCR-policy enforcement that doesn't exist")
}

func TestTPMKeyProvider_Errors(t *testing.T) {
	t.Run("blob path required", func(t *testing.T) {
		_, err := NewTPMKeyProvider("", "", "").KEK()
		require.Error(t, err)
	})
	t.Run("corrupt blob rejected", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "kek.tpm"), []byte("not-json"), 0600))
		_, err := newTPMProvider(t, dir, 5).KEK()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "corrupt sealed blob")
	})
}
