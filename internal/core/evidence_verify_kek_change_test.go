package core

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
)

func writeEvidenceTestKEK(t *testing.T, path string) {
	t.Helper()
	raw := make([]byte, crypto.KEKSize)
	_, err := io.ReadFull(rand.Reader, raw)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte(hex.EncodeToString(raw)), 0o600))
}

// evidenceCoreFor wires a core with the evidence-signing key a real KeyManager
// derives from the KEK in kekPath, exactly as server/wire_encryption.go does.
func evidenceCoreFor(t *testing.T, dir, kekPath string) *KeyorixCore {
	t.Helper()
	km := encryption.NewKeyManager(dir, "dek.key", "kek.salt")
	km.SetKeyProvider(crypto.NewFileKeyProvider(kekPath))
	require.NoError(t, km.Initialize(""))
	key, ver, ok := km.GetEvidenceSignKey()
	require.True(t, ok)
	c := &KeyorixCore{}
	c.SetEvidenceSignKey(key, ver)
	return c
}

// TestEvidenceVerify_PackSignedBeforeKEKChangeIsUnverifiable pins the sentence in
// openapi.yaml (verifyComplianceEvidence) and docs: the evidence-signing key is
// KEK-derived, so a pack signed under the old KEK is reported unverifiable (not
// valid, and not a tamper mismatch) once the KEK has changed, and the same pack
// still verifies while the KEK is unchanged. That a DEK rotation leaves the key
// alone is pinned in internal/encryption (TestEvidenceSignKey_StableAcrossDEKRotation).
func TestEvidenceVerify_PackSignedBeforeKEKChangeIsUnverifiable(t *testing.T) {
	dir := t.TempDir()
	oldKEK := filepath.Join(dir, "old.kek")
	newKEK := filepath.Join(dir, "new.kek")
	writeEvidenceTestKEK(t, oldKEK)
	writeEvidenceTestKEK(t, newKEK)

	before := evidenceCoreFor(t, dir, oldKEK)
	const fname = "keyorix-evidence-20260615T000000Z.json"
	data := []byte(`{"generated_at":"2026-06-15T00:00:00Z"}`)
	sig, ok := before.signEvidence(fname, data)
	require.True(t, ok)

	// Same KEK (e.g. a restart, or a DEK rotation): still verifies.
	same := evidenceCoreFor(t, t.TempDir(), oldKEK)
	assert.True(t, same.VerifyEvidenceSignature(fname, data, sig).Valid)

	// New KEK: unverifiable, naming both key versions, not a tamper mismatch.
	after := evidenceCoreFor(t, t.TempDir(), newKEK)
	res := after.VerifyEvidenceSignature(fname, data, sig)
	assert.False(t, res.Valid)
	assert.Contains(t, res.Reason, "superseded")
	assert.NotContains(t, res.Reason, "does not match")
	assert.NotEmpty(t, res.KeyVersion)
	assert.NotEmpty(t, res.CurrentVersion)
	assert.NotEqual(t, res.KeyVersion, res.CurrentVersion)
}
