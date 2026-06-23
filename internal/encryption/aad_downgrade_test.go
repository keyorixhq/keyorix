package encryption

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFileProviderService builds an initialized file-provider Service over a temp dir, the
// same way the end-to-end service tests do.
func newFileProviderService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "kek.bin")
	require.NoError(t, os.WriteFile(keyPath, bytes.Repeat([]byte{0x42}, 32), 0600))
	cfg := &config.EncryptionConfig{
		Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt",
		KeyProvider: config.KeyProviderConfig{Type: "file", FilePath: keyPath},
	}
	s := NewService(cfg, dir)
	require.NoError(t, s.Initialize(""))
	return s
}

// TestAAD_NoLegacyDowngradeBypass pins the security boundary of the legacy nil-AAD
// fallback in DecryptSecretWithAAD. The fallback exists for backward compatibility: a row
// with no AADVersion (encrypted before the AAD migration) decrypts on the plain, nil-AAD
// path. The risk is a DOWNGRADE: an attacker with DB write access takes a v2 (AAD-sealed)
// ciphertext, clears its AADVersion flag to force the legacy path, and so sidesteps the
// transplant binding (SecretAAD). This must NOT work — the GCM tag, not the metadata flag,
// is the real boundary: a ciphertext sealed with AAD simply cannot open with nil AAD, so a
// downgraded row fails closed (at worst it bricks the row; it can never transplant).
func TestAAD_NoLegacyDowngradeBypass(t *testing.T) {
	s := newFileProviderService(t)
	plaintext := []byte("value of secret A")
	aadA := SecretAAD(100, 7, 3) // the row's true (secret, project, version)
	aadB := SecretAAD(101, 7, 3) // a different secret an attacker wants to transplant into

	ct, _, err := s.EncryptSecretWithAAD(plaintext, aadA)
	require.NoError(t, err)

	// Sanity: the v2 row carries the AADVersion marker and enforces its AAD.
	enc, err := DeserializeEncryptedData(ct)
	require.NoError(t, err)
	require.Equal(t, "v2", enc.Metadata.AADVersion, "an AAD-sealed row must be marked v2")

	got, err := s.DecryptSecretWithAAD(ct, aadA)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got, "the correct AAD round-trips")

	_, err = s.DecryptSecretWithAAD(ct, aadB)
	require.Error(t, err, "a different secret's AAD must not open the ciphertext (transplant blocked)")

	// The downgrade attack: strip the AADVersion flag to force the legacy nil-AAD path.
	enc.Metadata.AADVersion = ""
	downgraded, err := SerializeEncryptedData(enc)
	require.NoError(t, err)

	// Even with the flag cleared, the ciphertext was sealed WITH AAD — the legacy plain
	// path opens with nil AAD and the GCM tag check fails. Try every avenue an attacker has:
	_, err = s.DecryptSecretWithAAD(downgraded, aadB)
	require.Error(t, err, "downgrade + target AAD must not transplant the ciphertext")
	_, err = s.DecryptSecretWithAAD(downgraded, aadA)
	require.Error(t, err, "downgrade must not open even with the original AAD (legacy path ignores it)")
	_, err = s.DecryptSecret(downgraded)
	require.Error(t, err, "the plain decrypt path must not open an AAD-sealed ciphertext")
}

// TestAAD_LegacyRowStillDecrypts documents the deliberate backward-compatibility side of
// the same branch: a genuinely legacy row (sealed without AAD, AADVersion absent) decrypts
// on the plain path regardless of any AAD passed. Such rows are NOT transplant-protected —
// that is the known pre-migration limitation the M2 re-encryption sweep removes — but they
// must keep decrypting so an upgrade never strands existing data. Pinning this keeps the
// branch's two halves explicit: AADVersion set ⇒ AAD enforced (see the downgrade test
// above); AADVersion absent ⇒ legacy passthrough.
func TestAAD_LegacyRowStillDecrypts(t *testing.T) {
	s := newFileProviderService(t)
	plaintext := []byte("pre-migration legacy value")

	// EncryptSecret (no AAD) stands in for a row written before the AAD migration.
	ct, _, err := s.EncryptSecret(plaintext)
	require.NoError(t, err)
	enc, err := DeserializeEncryptedData(ct)
	require.NoError(t, err)
	require.Empty(t, enc.Metadata.AADVersion, "a legacy row carries no AADVersion marker")

	// The legacy row decrypts on the AAD-aware path via the fallback, ignoring the AAD.
	got, err := s.DecryptSecretWithAAD(ct, SecretAAD(1, 1, 1))
	require.NoError(t, err)
	assert.Equal(t, plaintext, got, "a legacy row must keep decrypting after the upgrade")
}
