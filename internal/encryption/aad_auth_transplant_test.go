package encryption

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAEAD_MFASecretAADBindsCiphertextToOwningUser pins the #94 fix for TOTP shared
// secrets: a ciphertext sealed with MFASecretAAD(userID) cannot be decrypted under a
// different user's identity. Without this, a DB-write attacker could copy user A's
// encrypted TOTP seed into user B's mfa_secrets row — B's login would then accept
// codes generated from A's seed (a stealthy, persistent MFA bypass).
func TestAEAD_MFASecretAADBindsCiphertextToOwningUser(t *testing.T) {
	es := newTestEncryptionService(t)
	plaintext := []byte("JBSWY3DPEHPK3PXP") // a base32 TOTP seed shape

	aadA := MFASecretAAD(42)
	enc, err := es.EncryptWithAAD(plaintext, testKeyVersion, aadA)
	require.NoError(t, err)

	got, err := es.DecryptWithAAD(enc, aadA)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(plaintext, got), "the binding AAD must round-trip")

	_, err = es.DecryptWithAAD(enc, MFASecretAAD(43))
	require.Error(t, err, "a TOTP seed ciphertext transplanted onto a different user's row must not decrypt")
}

// TestAEAD_DynamicSecretConfigAADBindsCiphertextToOwningConfig pins the #94 fix for
// dynamic-secret admin DSNs: a ciphertext sealed with
// DynamicSecretConfigAAD(id, projectID, environmentID) cannot be decrypted under a
// different config's identity, project, or environment. Without this, an attacker
// could transplant one target's encrypted admin credential onto a DIFFERENT config
// row and have Keyorix connect to the wrong (attacker's own, or another tenant's)
// database using credentials it was never authorized to use for that config.
func TestAEAD_DynamicSecretConfigAADBindsCiphertextToOwningConfig(t *testing.T) {
	es := newTestEncryptionService(t)
	plaintext := []byte("postgres://admin:s3cr3t@db.internal:5432/app")

	aadA := DynamicSecretConfigAAD(10, 1, 2)
	enc, err := es.EncryptWithAAD(plaintext, testKeyVersion, aadA)
	require.NoError(t, err)

	got, err := es.DecryptWithAAD(enc, aadA)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(plaintext, got), "the binding AAD must round-trip")

	_, err = es.DecryptWithAAD(enc, DynamicSecretConfigAAD(11, 1, 2))
	require.Error(t, err, "an admin DSN transplanted onto a different config ID must not decrypt")
	_, err = es.DecryptWithAAD(enc, DynamicSecretConfigAAD(10, 3, 2))
	require.Error(t, err, "an admin DSN relabeled to a different project must not decrypt")
	_, err = es.DecryptWithAAD(enc, DynamicSecretConfigAAD(10, 1, 5))
	require.Error(t, err, "an admin DSN relabeled to a different environment must not decrypt")
}

// TestAEAD_DynamicSecretLeaseAADBindsCiphertextToOwningLease pins the #94 fix for
// issued dynamic-secret credentials: a ciphertext sealed with
// DynamicSecretLeaseAAD(leaseID, configID) cannot be decrypted under a different
// lease or a different owning config. Without this, an attacker could transplant one
// principal's issued credential (returned once, on issue) onto another lease row and
// have RevokeLease/RenewLease act on it under the wrong identity.
func TestAEAD_DynamicSecretLeaseAADBindsCiphertextToOwningLease(t *testing.T) {
	es := newTestEncryptionService(t)
	plaintext := []byte(`{"username":"kx_role_abc","password":"hunter2"}`)

	aadA := DynamicSecretLeaseAAD("lease-aaa", 5)
	enc, err := es.EncryptWithAAD(plaintext, testKeyVersion, aadA)
	require.NoError(t, err)

	got, err := es.DecryptWithAAD(enc, aadA)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(plaintext, got), "the binding AAD must round-trip")

	_, err = es.DecryptWithAAD(enc, DynamicSecretLeaseAAD("lease-bbb", 5))
	require.Error(t, err, "a credential transplanted onto a different lease ID must not decrypt")
	_, err = es.DecryptWithAAD(enc, DynamicSecretLeaseAAD("lease-aaa", 6))
	require.Error(t, err, "a credential relabeled to a different owning config must not decrypt")
}
