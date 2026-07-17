package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateKEK_S21 exercises validateKEK directly: the shared guard that every
// provider calls before returning key material.
func TestValidateKEK_S21(t *testing.T) {
	t.Run("valid 32-byte key accepted", func(t *testing.T) {
		key := make([]byte, KEKSize)
		for i := range key {
			key[i] = byte(i + 1)
		}
		got, err := validateKEK(key, "test")
		require.NoError(t, err)
		assert.Equal(t, key, got)
	})

	t.Run("too short rejected", func(t *testing.T) {
		_, err := validateKEK(make([]byte, 16), "test")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "32 bytes")
	})

	t.Run("too long rejected", func(t *testing.T) {
		_, err := validateKEK(make([]byte, 64), "test")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "32 bytes")
	})

	t.Run("empty slice rejected", func(t *testing.T) {
		_, err := validateKEK([]byte{}, "test")
		require.Error(t, err)
	})

	t.Run("all-zero key rejected", func(t *testing.T) {
		_, err := validateKEK(make([]byte, KEKSize), "test")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "all-zero")
	})

	t.Run("provider name appears in error", func(t *testing.T) {
		_, err := validateKEK(make([]byte, KEKSize), "my-provider")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "my-provider")
	})

	t.Run("key with only last byte set is not all-zero", func(t *testing.T) {
		key := make([]byte, KEKSize)
		key[KEKSize-1] = 0x01
		got, err := validateKEK(key, "test")
		require.NoError(t, err)
		assert.Equal(t, key, got)
	})
}

// TestLimitedBuffer_S21 exercises the limitedBuffer.Write path that discards
// further output once the cap has been exceeded — the branch at 87.5% in exec_provider.go.
func TestLimitedBuffer_S21(t *testing.T) {
	t.Run("write within cap accumulates", func(t *testing.T) {
		b := &limitedBuffer{max: 10}
		n, err := b.Write([]byte("hello"))
		require.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.False(t, b.exceeded)
		assert.Equal(t, []byte("hello"), b.buf.Bytes())
	})

	t.Run("write at exact cap does not set exceeded", func(t *testing.T) {
		b := &limitedBuffer{max: 5}
		n, err := b.Write([]byte("hello"))
		require.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.False(t, b.exceeded)
	})

	t.Run("write that crosses cap sets exceeded and truncates buffer", func(t *testing.T) {
		b := &limitedBuffer{max: 3}
		n, err := b.Write([]byte("hello"))
		require.NoError(t, err)
		// Write returns len(p) even when truncated — caller sees no error.
		assert.Equal(t, 5, n)
		assert.True(t, b.exceeded)
		// Only the bytes that fit were kept.
		assert.Equal(t, []byte("hel"), b.buf.Bytes())
	})

	t.Run("subsequent write after exceeded is discarded", func(t *testing.T) {
		b := &limitedBuffer{max: 2}
		_, _ = b.Write([]byte("abcde")) // sets exceeded, keeps "ab"
		assert.True(t, b.exceeded)

		// This write should be discarded completely (already exceeded).
		n, err := b.Write([]byte("more data"))
		require.NoError(t, err)
		assert.Equal(t, 9, n, "Write must return len(p) even when discarding")
		// Buffer still only has the original "ab".
		assert.Equal(t, []byte("ab"), b.buf.Bytes())
	})

	t.Run("empty write on empty buffer", func(t *testing.T) {
		b := &limitedBuffer{max: 10}
		n, err := b.Write(nil)
		require.NoError(t, err)
		assert.Equal(t, 0, n)
		assert.False(t, b.exceeded)
	})
}

// TestProviderName_S21 exercises the Name() methods that report 0% coverage:
// KMSKeyProvider, PasswordKeyProvider, FileKeyProvider, EnvKeyProvider all have
// a trivial one-line Name() that was never directly called in the existing tests.
func TestProviderName_S21(t *testing.T) {
	t.Run("KMSKeyProvider.Name", func(t *testing.T) {
		p := NewKMSKeyProvider(&fakeKMS{tag: "x"}, "gcp-kms", "", "k.kms")
		assert.Equal(t, "gcp-kms", p.Name())
	})

	t.Run("PasswordKeyProvider.Name", func(t *testing.T) {
		p := NewPasswordKeyProvider("passphrase", t.TempDir(), "s.salt")
		assert.Equal(t, "password", p.Name())
	})

	t.Run("FileKeyProvider.Name", func(t *testing.T) {
		p := NewFileKeyProvider("/some/path")
		assert.Equal(t, "file", p.Name())
	})

	t.Run("EnvKeyProvider.Name", func(t *testing.T) {
		p := NewEnvKeyProvider("MY_KEK")
		assert.Equal(t, "env", p.Name())
	})
}

// TestNewTPMKeyProvider_DefaultDevice_S21 verifies that NewTPMKeyProvider defaults
// an empty devicePath to DefaultTPMDevice (the branch at 83.3% in tpm_provider.go).
func TestNewTPMKeyProvider_DefaultDevice_S21(t *testing.T) {
	p := NewTPMKeyProvider("", "/tmp/base", "blob.tpm")
	assert.Equal(t, DefaultTPMDevice, p.devicePath,
		"an empty devicePath must default to DefaultTPMDevice")
	assert.Equal(t, "/tmp/base", p.baseDir)
	assert.Equal(t, "blob.tpm", p.blobPath)
}

// TestNewTPMKeyProvider_ExplicitDevice_S21 verifies that an explicit device path
// is kept as-is (the other branch of the defaulting if in NewTPMKeyProvider).
func TestNewTPMKeyProvider_ExplicitDevice_S21(t *testing.T) {
	p := NewTPMKeyProvider("/dev/tpm0", "/base", "key.tpm")
	assert.Equal(t, "/dev/tpm0", p.devicePath)
}

// TestTPMKeyProvider_BlobPathRequired_S21 is a direct test of the empty-blobPath
// guard in KEK(), which is tested indirectly in tpm_provider_test.go but included
// here to drive the statement explicitly through this file.
func TestTPMKeyProvider_BlobPathRequired_S21(t *testing.T) {
	_, err := NewTPMKeyProvider("", "", "").KEK()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrapped_key_path")
}

// TestKMSKeyProvider_Name_S21 confirms that the Name() method on KMSKeyProvider
// returns whatever string was passed to NewKMSKeyProvider (0% in coverage report).
func TestKMSKeyProvider_Name_S21(t *testing.T) {
	p := NewKMSKeyProvider(&fakeKMS{tag: "k"}, "aws-kms-custom", "", "k.kms")
	assert.Equal(t, "aws-kms-custom", p.Name())
}
