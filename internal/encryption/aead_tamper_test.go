package encryption

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestEncryptionService(t *testing.T) *EncryptionService {
	t.Helper()
	kek, err := GenerateRandomKey(32)
	require.NoError(t, err)
	es, err := NewEncryptionService(kek)
	require.NoError(t, err)
	return es
}

// TestAEAD_CiphertextTamperFailsClosed pins the core AEAD integrity guarantee: any
// modification of the sealed ciphertext, its appended GCM tag, or its nonce must make
// decryption FAIL — never return altered or garbage plaintext. AES-256-GCM authenticates
// all of these, but the guarantee only protects a secret if it actually fails closed: a
// regression to an unauthenticated mode, or one that dropped the tag check, would silently
// hand back attacker-influenced plaintext for a stored secret. Each subtest corrupts one
// authenticated region and asserts an error.
func TestAEAD_CiphertextTamperFailsClosed(t *testing.T) {
	es := newTestEncryptionService(t)
	plaintext := []byte("burn-after-reading top secret")

	t.Run("flipped ciphertext byte", func(t *testing.T) {
		enc, err := es.Encrypt(plaintext, testKeyVersion)
		require.NoError(t, err)
		enc.Data[len(enc.Data)/2] ^= 0x01 // flip one bit mid-ciphertext
		_, err = es.Decrypt(enc)
		require.Error(t, err, "a tampered ciphertext must fail to decrypt, not return garbage")
	})

	t.Run("flipped GCM tag byte", func(t *testing.T) {
		enc, err := es.Encrypt(plaintext, testKeyVersion)
		require.NoError(t, err)
		enc.Data[len(enc.Data)-1] ^= 0x80 // the GCM tag is appended to the ciphertext
		_, err = es.Decrypt(enc)
		require.Error(t, err, "a tampered GCM tag must fail to decrypt")
	})

	t.Run("tampered nonce", func(t *testing.T) {
		enc, err := es.Encrypt(plaintext, testKeyVersion)
		require.NoError(t, err)
		nonce, err := base64.StdEncoding.DecodeString(enc.Metadata.Nonce)
		require.NoError(t, err)
		nonce[0] ^= 0x01
		enc.Metadata.Nonce = base64.StdEncoding.EncodeToString(nonce)
		_, err = es.Decrypt(enc)
		require.Error(t, err, "a tampered nonce must fail to decrypt")
	})

	t.Run("truncated ciphertext", func(t *testing.T) {
		enc, err := es.Encrypt(plaintext, testKeyVersion)
		require.NoError(t, err)
		enc.Data = enc.Data[:len(enc.Data)-1] // drop a byte — also corrupts the tag
		_, err = es.Decrypt(enc)
		require.Error(t, err, "a truncated ciphertext must fail to decrypt")
	})

	t.Run("control: untampered round-trips", func(t *testing.T) {
		enc, err := es.Encrypt(plaintext, testKeyVersion)
		require.NoError(t, err)
		got, err := es.Decrypt(enc)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(plaintext, got), "an untampered ciphertext must round-trip")
	})
}

// TestAEAD_AADBindsCiphertextToItsSecret pins the ciphertext-transplant defense. A secret
// value is sealed with AAD = SecretAAD(secretID, projectID, versionNumber), so a ciphertext
// authenticated for one (secret, project, version) tuple cannot be decrypted under any
// other. An attacker with DB write access therefore cannot move secret A's encrypted value
// into secret B's row, relabel its project, or roll a value back by pasting a newer
// version's ciphertext into an older row — every such transplant fails the AAD check.
func TestAEAD_AADBindsCiphertextToItsSecret(t *testing.T) {
	es := newTestEncryptionService(t)
	plaintext := []byte("value of secret A")

	aadA := SecretAAD(100, 7, 3) // secret 100, project 7, version 3
	enc, err := es.EncryptWithAAD(plaintext, testKeyVersion, aadA)
	require.NoError(t, err)

	// The correct AAD round-trips.
	got, err := es.DecryptWithAAD(enc, aadA)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(plaintext, got), "the binding AAD must round-trip")

	// Transplant to a different SECRET (same project/version) is rejected.
	_, err = es.DecryptWithAAD(enc, SecretAAD(101, 7, 3))
	require.Error(t, err, "ciphertext must not decrypt under a different secret ID")

	// Relabel to a different PROJECT is rejected.
	_, err = es.DecryptWithAAD(enc, SecretAAD(100, 8, 3))
	require.Error(t, err, "ciphertext must not decrypt under a different project ID")

	// Version-rollback transplant (paste v3 ciphertext where v2 is expected) is rejected.
	_, err = es.DecryptWithAAD(enc, SecretAAD(100, 7, 2))
	require.Error(t, err, "ciphertext must not decrypt under a different version (rollback defense)")
}

// TestAEAD_AADBindingIsMandatory pins that the AAD channel is genuinely bound, not
// cosmetic: data sealed WITH an AAD cannot be opened on the plain (nil-AAD) path, and data
// sealed WITHOUT an AAD cannot be opened under a non-nil AAD. This guards against a
// regression that quietly ignored the AAD (e.g. always passing nil), which would silently
// void the transplant defense above while every happy-path round-trip test still passed.
func TestAEAD_AADBindingIsMandatory(t *testing.T) {
	es := newTestEncryptionService(t)
	plaintext := []byte("bound to context")
	aad := SecretAAD(1, 1, 1)

	withAAD, err := es.EncryptWithAAD(plaintext, testKeyVersion, aad)
	require.NoError(t, err)
	_, err = es.Decrypt(withAAD) // plain Decrypt opens with nil AAD
	require.Error(t, err, "data sealed with AAD must not open without it")

	plain, err := es.Encrypt(plaintext, testKeyVersion)
	require.NoError(t, err)
	_, err = es.DecryptWithAAD(plain, aad)
	require.Error(t, err, "data sealed without AAD must not open under a non-nil AAD")
}
