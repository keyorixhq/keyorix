package auditverify

import (
	"bytes"
	"crypto/sha256"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func TestDeriveBackupManifestKey_DeterministicForTheSameKEK(t *testing.T) {
	kek := bytes.Repeat([]byte{0x42}, 32)
	key1, id1, err := DeriveBackupManifestKey(kek)
	require.NoError(t, err)
	key2, id2, err := DeriveBackupManifestKey(kek)
	require.NoError(t, err)
	require.Equal(t, key1, key2)
	require.Equal(t, id1, id2)
}

func TestDeriveBackupManifestKey_DiffersForDifferentKEKs(t *testing.T) {
	key1, id1, err := DeriveBackupManifestKey(bytes.Repeat([]byte{0x01}, 32))
	require.NoError(t, err)
	key2, id2, err := DeriveBackupManifestKey(bytes.Repeat([]byte{0x02}, 32))
	require.NoError(t, err)
	require.NotEqual(t, key1, key2)
	require.NotEqual(t, id1, id2)
}

func TestDeriveBackupManifestKey_ShapeAndPrefix(t *testing.T) {
	key, id, err := DeriveBackupManifestKey(bytes.Repeat([]byte{0x03}, 32))
	require.NoError(t, err)
	require.Len(t, key, 32)
	require.True(t, strings.HasPrefix(id, "bmk-"))
}

// TestDeriveBackupManifestKey_DomainSeparatedFromAuditCheckpointKey is
// design §5.2's own stated concern made concrete: the manifest key must
// never equal what a DIFFERENT HKDF info string derives from the same KEK
// -- this package can't import internal/encryption's actual
// deriveAuditCheckpointKey (dependency guard), so this instead proves the
// derivation is SENSITIVE to the info string at all, i.e. that swapping in
// a different info label changes the output, which is the property
// domain-separation actually depends on holding.
func TestDeriveBackupManifestKey_DomainSeparatedFromAuditCheckpointKey(t *testing.T) {
	kek := bytes.Repeat([]byte{0x09}, 32)
	manifestKey, _, err := DeriveBackupManifestKey(kek)
	require.NoError(t, err)

	// Same HKDF construction, DIFFERENT info string (the one
	// internal/encryption's auditCheckpointKeyInfo actually uses) --
	// mirrors this package's own checkpoint.go/HighWaterSigMatches pattern
	// of independently re-deriving rather than importing.
	otherKeyR := hkdf.New(sha256.New, kek, nil, []byte("keyorix-audit-checkpoint-kek-v2"))
	otherKey := make([]byte, 32)
	_, err = io.ReadFull(otherKeyR, otherKey)
	require.NoError(t, err)

	require.NotEqual(t, manifestKey, otherKey,
		"the manifest-signing key must never equal what the audit-checkpoint key's own info string would derive")
}
