package crypto

// Tests added for the gremlins survivors in raw_providers.go and
// exec_provider.go, plus value pins for const expressions gremlins reports as
// NOT COVERED (#3612, MUTANT-CRYPTO-1).

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// raw_providers.go:88 and exec_provider.go:126 — trailing CR/LF is trimmed only
// when the material is NOT exactly KEKSize bytes. A raw 32-byte key whose last
// byte happens to be '\n' (or '\r') must come back intact.
func TestRawKeyMaterial_ExactlyKEKSizeEndingInNewlineIsNotTrimmed(t *testing.T) {
	for _, last := range []byte{'\n', '\r'} {
		raw := testKEK()
		raw[KEKSize-1] = last
		path := filepath.Join(t.TempDir(), "kek.bin")
		require.NoError(t, os.WriteFile(path, raw, 0o600))

		got, err := NewFileKeyProvider(path).KEK()
		require.NoError(t, err, "file provider, last byte %q", last)
		assert.Equal(t, raw, got)

		got, err = NewExecKeyProvider([]string{"cat", path}).KEK()
		require.NoError(t, err, "exec provider, last byte %q", last)
		assert.Equal(t, raw, got)
	}
}

// ... and an encoded form with a trailing newline (length != KEKSize) is trimmed.
func TestRawKeyMaterial_EncodedFormTrailingCRLFTrimmed(t *testing.T) {
	raw := testKEK()
	path := filepath.Join(t.TempDir(), "kek.hex")
	require.NoError(t, os.WriteFile(path, []byte(hex.EncodeToString(raw)+"\r\n"), 0o600))

	got, err := NewFileKeyProvider(path).KEK()
	require.NoError(t, err)
	assert.Equal(t, raw, got)
	got, err = NewExecKeyProvider([]string{"cat", path}).KEK()
	require.NoError(t, err)
	assert.Equal(t, raw, got)
}

// Constant pins: gremlins reports these const expressions as NOT COVERED (a
// const declaration has no coverage block, so no test can ever "cover" it) —
// the values are behaviour, so they are asserted directly.
func TestTimeoutConstants(t *testing.T) {
	assert.Equal(t, 30*time.Second, execKeyTimeout)
	assert.Equal(t, 30*time.Second, kmsCallTimeout)
	assert.Equal(t, 1<<20, execMaxStdoutBytes)
}
