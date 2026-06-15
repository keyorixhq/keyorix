package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShamirKeyProvider_Name(t *testing.T) {
	assert.Equal(t, "shamir", NewShamirKeyProvider(nil, nil).Name())
}

func TestShamirKeyProvider_CombinesSharesFromFilesAndEnv(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK() // 32 bytes
	shares, err := Split(kek, 5, 3)
	require.NoError(t, err)

	// Two shares as hex files, one as a base64 env var → threshold 3 reached.
	f1 := filepath.Join(dir, "s1")
	f2 := filepath.Join(dir, "s2")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])+"\n"), 0600))
	require.NoError(t, os.WriteFile(f2, []byte(hex.EncodeToString(shares[1])), 0600))
	t.Setenv("KX_SHARE_3", base64.StdEncoding.EncodeToString(shares[2]))

	got, err := NewShamirKeyProvider([]string{f1, f2}, []string{"KX_SHARE_3"}).KEK()
	require.NoError(t, err)
	assert.Equal(t, kek, got)
}

func TestShamirKeyProvider_TooFewSharesFailsClosed(t *testing.T) {
	dir := t.TempDir()
	kek := testKEK()
	shares, err := Split(kek, 5, 3)
	require.NoError(t, err)
	f1 := filepath.Join(dir, "s1")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0600))

	// Only one share configured — below the minimum, rejected outright.
	_, err = NewShamirKeyProvider([]string{f1}, nil).KEK()
	require.Error(t, err)
}

func TestShamirKeyProvider_WrongLengthSecretRejected(t *testing.T) {
	dir := t.TempDir()
	// Split a NON-32-byte secret: combining recovers it, but the KEK size check rejects.
	shares, err := Split([]byte("not-thirty-two-bytes"), 3, 2)
	require.NoError(t, err)
	f1 := filepath.Join(dir, "s1")
	f2 := filepath.Join(dir, "s2")
	require.NoError(t, os.WriteFile(f1, []byte(hex.EncodeToString(shares[0])), 0600))
	require.NoError(t, os.WriteFile(f2, []byte(hex.EncodeToString(shares[1])), 0600))

	_, err = NewShamirKeyProvider([]string{f1, f2}, nil).KEK()
	require.Error(t, err, "a reconstructed secret that isn't 32 bytes must be rejected")
}

func TestShamirKeyProvider_Errors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		_, err := NewShamirKeyProvider([]string{filepath.Join(t.TempDir(), "nope")}, nil).KEK()
		require.Error(t, err)
	})
	t.Run("unset env", func(t *testing.T) {
		_, err := NewShamirKeyProvider(nil, []string{"KX_SHARE_DOES_NOT_EXIST"}).KEK()
		require.Error(t, err)
	})
	t.Run("garbage share", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "g")
		require.NoError(t, os.WriteFile(f, []byte("!"), 0600))
		_, err := NewShamirKeyProvider([]string{f}, []string{}).KEK()
		require.Error(t, err)
	})
}
