package backupfmt

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
)

func testFixtureManifest() Manifest {
	return Manifest{
		FormatVersion: FormatVersion,
		Backend:       Backend,
		CreatedAt:     time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC),
		SchemaEpoch:   7,
		Tables: []TableEntry{
			{Name: "users", TarName: "tables/users.ndjson", RowCount: 2, UncompressedSize: 123, SHA256: "abc123"},
			{Name: "projects", TarName: "tables/projects.ndjson", RowCount: 1, UncompressedSize: 45, SHA256: "def456"},
		},
		KeyFiles: []KeyFileEntry{
			{OriginalPath: "dek.key", TarName: "keyfiles/0", Mode: 0600, SHA256: "ghi789", Size: 32},
		},
		Checkpoint: &auditverify.ExternalAnchorBundle{
			ChainedEvents: 42,
			HeadID:        99,
			HeadHash:      "headhash",
			KeyVersion:    "v1",
			Signature:     "checkpointsig",
		},
	}
}

func TestSignManifest_ThenVerifySucceeds(t *testing.T) {
	m := testFixtureManifest()
	key := testManifestKey()
	require.NoError(t, SignManifest(&m, key))
	require.NotEmpty(t, m.Signature)
	require.True(t, VerifyManifestSignature(m, key))
}

func TestVerifyManifestSignature_FailsOnWrongKey(t *testing.T) {
	m := testFixtureManifest()
	require.NoError(t, SignManifest(&m, testManifestKey()))
	wrongKey := append([]byte{}, testManifestKey()...)
	wrongKey[0] ^= 0xFF
	require.False(t, VerifyManifestSignature(m, wrongKey))
}

func TestVerifyManifestSignature_EmptySignatureFails(t *testing.T) {
	m := testFixtureManifest()
	require.False(t, VerifyManifestSignature(m, testManifestKey()))
}

// TestVerifyManifestSignature_TamperedPayloadUntouchedSignature is design
// §11.4's "red — tampered payload, untouched signature": flip a value in a
// signed field (a table's row count, standing in for tampered NDJSON
// content the manifest's own hash would also cover once wired into a real
// restore) without recomputing the signature. Verification must refuse.
func TestVerifyManifestSignature_TamperedPayloadUntouchedSignature(t *testing.T) {
	m := testFixtureManifest()
	require.NoError(t, SignManifest(&m, testManifestKey()))

	m.Tables[0].RowCount = 999999 // tamper AFTER signing, signature left stale
	require.False(t, VerifyManifestSignature(m, testManifestKey()))
}

// TestVerifyManifestSignature_ContentAndChecksumAlteredSignatureStale is
// design §11.4's specific case for why a checksum alone isn't authenticity:
// an attacker who can edit the archive can also recompute a per-table
// checksum to match tampered content, but cannot recompute the manifest's
// OWN HMAC without the key. Simulated here by altering both a table's
// declared SHA256 (the "recomputed checksum") and its RowCount (the
// "tampered content") together, leaving only the manifest signature stale.
func TestVerifyManifestSignature_ContentAndChecksumAlteredSignatureStale(t *testing.T) {
	m := testFixtureManifest()
	require.NoError(t, SignManifest(&m, testManifestKey()))

	m.Tables[0].RowCount = 3
	m.Tables[0].SHA256 = "attacker-recomputed-checksum-that-matches-the-tampered-content"
	require.False(t, VerifyManifestSignature(m, testManifestKey()))
}

// TestVerifyManifestSignature_ExhaustiveSingleByteTamper is design §11.4's
// exhaustive byte-flip requirement, applied to the manifest itself (the
// per-table/checkpoint tamper_exhaustive_test.go pattern PR #2097
// introduced for the audit chain, extended here to the new manifest
// signature): for every byte offset in the signed manifest's JSON encoding,
// flip it and confirm the mutated manifest never verifies. A mutation that
// breaks JSON parsing entirely is an equally-refused case in the real
// restore path (readBackupArchive fails before verification is even
// reached), so it's excluded here as "trivially refused," not skipped as
// untested.
func TestVerifyManifestSignature_ExhaustiveSingleByteTamper(t *testing.T) {
	m := testFixtureManifest()
	key := testManifestKey()
	require.NoError(t, SignManifest(&m, key))

	original, err := json.Marshal(m)
	require.NoError(t, err)

	checked := 0
	for i := range original {
		mutated := append([]byte{}, original...)
		mutated[i] ^= 0xFF
		if mutated[i] == original[i] {
			continue // XOR 0xFF is only a no-op if the byte was already 0xFF, impossible for ASCII JSON -- defensive only
		}

		var candidate Manifest
		if err := json.Unmarshal(mutated, &candidate); err != nil {
			continue // unparseable -- refused earlier in the real restore path, not this function's job to catch
		}
		checked++
		require.False(t, VerifyManifestSignature(candidate, key),
			"byte offset %d: mutated manifest must not verify (original byte %#x -> %#x)", i, original[i], mutated[i])
	}
	require.Greater(t, checked, 0, "the byte-flip loop must actually have exercised at least one parseable mutant")
}
