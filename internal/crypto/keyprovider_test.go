package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/pbkdf2"
)

func TestPasswordKeyProvider_DeterministicAndMatchesLegacyKDF(t *testing.T) {
	dir := t.TempDir()
	p := NewPasswordKeyProvider("correct horse battery staple", dir, "kek.salt")

	kek1, err := p.KEK()
	require.NoError(t, err)
	require.Len(t, kek1, KEKSize)

	// Salt was persisted; a second call (and a fresh provider over the same dir)
	// derives the identical KEK.
	kek2, err := p.KEK()
	require.NoError(t, err)
	assert.Equal(t, kek1, kek2, "KEK must be stable for a fixed passphrase + salt")

	salt, err := os.ReadFile(filepath.Join(dir, "kek.salt"))
	require.NoError(t, err)
	require.Len(t, salt, saltSize)

	// Byte-identity with the historical derivation (PBKDF2-SHA256, 600000, 32).
	want := pbkdf2.Key([]byte("correct horse battery staple"), salt, 600000, KEKSize, sha256.New)
	assert.Equal(t, want, kek1, "password provider must reproduce the legacy KEK derivation exactly")

	p2 := NewPasswordKeyProvider("correct horse battery staple", dir, "kek.salt")
	kek3, err := p2.KEK()
	require.NoError(t, err)
	assert.Equal(t, kek1, kek3, "a fresh provider over the same salt derives the same KEK")
}

func TestPasswordKeyProvider_EmptyPassphraseRejected(t *testing.T) {
	_, err := NewPasswordKeyProvider("", t.TempDir(), "kek.salt").KEK()
	require.Error(t, err)
}

func TestFileKeyProvider_AcceptsRawHexBase64(t *testing.T) {
	dir := t.TempDir()
	raw := make([]byte, KEKSize)
	for i := range raw {
		raw[i] = byte(i + 1)
	}

	cases := map[string][]byte{
		"raw":        raw,
		"hex":        []byte(hex.EncodeToString(raw)),
		"base64":     []byte(base64.StdEncoding.EncodeToString(raw)),
		"hex+nl":     []byte(hex.EncodeToString(raw) + "\n"),
		"base64+nl":  []byte(base64.StdEncoding.EncodeToString(raw) + "\n"),
		"base64-raw": []byte(base64.RawStdEncoding.EncodeToString(raw)),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".key")
			require.NoError(t, os.WriteFile(path, content, 0600))
			kek, err := NewFileKeyProvider(path).KEK()
			require.NoError(t, err)
			assert.Equal(t, raw, kek)
		})
	}
}

func TestFileKeyProvider_Errors(t *testing.T) {
	dir := t.TempDir()
	t.Run("missing path", func(t *testing.T) {
		_, err := NewFileKeyProvider("").KEK()
		require.Error(t, err)
	})
	t.Run("nonexistent file", func(t *testing.T) {
		_, err := NewFileKeyProvider(filepath.Join(dir, "nope.key")).KEK()
		require.Error(t, err)
	})
	t.Run("wrong-size key rejected", func(t *testing.T) {
		path := filepath.Join(dir, "short.key")
		require.NoError(t, os.WriteFile(path, []byte("tooshort"), 0600))
		_, err := NewFileKeyProvider(path).KEK()
		require.Error(t, err, "a key that doesn't decode to 32 bytes must be rejected")
	})
	t.Run("all-zero key rejected", func(t *testing.T) {
		path := filepath.Join(dir, "zero.key")
		require.NoError(t, os.WriteFile(path, make([]byte, KEKSize), 0600))
		_, err := NewFileKeyProvider(path).KEK()
		require.Error(t, err, "a zeroed/placeholder KEK must be rejected")
		assert.Contains(t, err.Error(), "all-zero")
	})
}

func TestEnvKeyProvider(t *testing.T) {
	raw := make([]byte, KEKSize)
	for i := range raw {
		raw[i] = byte(255 - i)
	}
	t.Setenv("KX_TEST_KEK", base64.StdEncoding.EncodeToString(raw))
	kek, err := NewEnvKeyProvider("KX_TEST_KEK").KEK()
	require.NoError(t, err)
	assert.Equal(t, raw, kek)

	t.Run("unset env rejected", func(t *testing.T) {
		_, err := NewEnvKeyProvider("KX_DOES_NOT_EXIST").KEK()
		require.Error(t, err)
	})
	t.Run("empty env_var rejected", func(t *testing.T) {
		_, err := NewEnvKeyProvider("").KEK()
		require.Error(t, err)
	})
	t.Run("garbage value rejected", func(t *testing.T) {
		t.Setenv("KX_TEST_BAD", "not-a-valid-key")
		_, err := NewEnvKeyProvider("KX_TEST_BAD").KEK()
		require.Error(t, err)
	})
}
