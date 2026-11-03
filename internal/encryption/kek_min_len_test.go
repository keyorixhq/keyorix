package encryption

import (
	"crypto/fips140"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/auditverify"
)

// kekGoldenPattern is the deterministic KEK the golden vectors below were
// computed from: byte i = i*7 + 3, truncated to the length under test. The
// vectors were recorded at edc8f0c5b (before the MinKEKLen guard existed),
// both with and without GODEBUG=fips140=only, so they prove the guard changed
// no derived key and therefore no stored checkpoint or evidence signature.
func kekGoldenPattern(n int) []byte {
	kek := make([]byte, n)
	for i := range kek {
		kek[i] = byte(i*7 + 3)
	}
	return kek
}

type kekGolden struct {
	key, id string
}

var kekGoldenVectors = map[int]map[string]kekGolden{
	14: {
		"evidence-signing": {"79406545023d064a002f740946f5b2962b581fa706114a696a4adf7ff9bd0f82", "esk-005afd98e6f0bd09cff0fbd070016394"},
		"audit-checkpoint": {"381242943be340a83c7102b1a13b6f8d199aadf5702991bd681aa571498ce1d5", "ack-ebee63b63a5b0d4353b9a58023f2231e"},
		"backup-manifest":  {"2425bb359686e31ebe7101e206de6c96a9bc6e5959fd39dda33068a1a43d8381", "bmk-206ae53e1f79b6f8946bb0e65b3cab6b"},
	},
	32: {
		"evidence-signing": {"232f79cfa354b41c7139b6cbb2c5e61ed662cd10543f6be293591cbf532af4dd", "esk-5969813624bdc9dce0e20c301ab46b80"},
		"audit-checkpoint": {"38c59512d8c9620020a5e836ff8c22a38c1772a66caccf5876295fe50a8a9aea", "ack-074e76ab22985b2d74319cd352b2632c"},
		"backup-manifest":  {"c61b28978e9a79eb968048179d79921558fb91e65b1563d39c9706c1ccfd5707", "bmk-e94287ee1756edccb269ad4032f17f75"},
	},
}

var kekDerivations = map[string]func([]byte) ([]byte, string, error){
	"evidence-signing": deriveEvidenceSignKey,
	"audit-checkpoint": deriveAuditCheckpointKey,
	"backup-manifest":  auditverify.DeriveBackupManifestKey,
}

// TestKEKDerivation_ShortKEKRefusedValidKEKGolden pins FIPS-TAILS-1 item 1:
// every KEK-derived HKDF key refuses a KEK below MinKEKLen with a typed
// *KEKTooShortError and no key material, and derives byte-identical keys for
// valid lengths. Before the guard, the short cases panicked under
// GODEBUG=fips140=only ("crypto/hkdf: use of keys shorter than 112 bits is not
// allowed in FIPS 140-only mode") and succeeded in default mode; the behaviour
// is now the same in both. Run it under both modes (the FIPS sweep does).
func TestKEKDerivation_ShortKEKRefusedValidKEKGolden(t *testing.T) {
	t.Logf("fips140.Enforced() = %v", fips140.Enforced())
	for name, derive := range kekDerivations {
		for _, n := range []int{0, 1, 13} {
			key, id, err := derive(kekGoldenPattern(n))
			if !errors.Is(err, ErrKEKTooShort) {
				t.Errorf("%s, %d-byte KEK: err = %v, want ErrKEKTooShort", name, n, err)
				continue
			}
			var tooShort *KEKTooShortError
			if !errors.As(err, &tooShort) || tooShort.Len != n {
				t.Errorf("%s, %d-byte KEK: err = %#v, want *KEKTooShortError{Len: %d}", name, n, err, n)
			}
			if key != nil || id != "" {
				t.Errorf("%s, %d-byte KEK: returned key %x / id %q with the error, want none", name, n, key, id)
			}
		}
		for n, byName := range kekGoldenVectors {
			want := byName[name]
			key, id, err := derive(kekGoldenPattern(n))
			if err != nil {
				t.Errorf("%s, %d-byte KEK: %v", name, n, err)
				continue
			}
			if got := hex.EncodeToString(key); got != want.key {
				t.Errorf("%s, %d-byte KEK: key = %s, want golden %s", name, n, got, want.key)
			}
			if id != want.id {
				t.Errorf("%s, %d-byte KEK: id = %s, want golden %s", name, n, id, want.id)
			}
		}
	}
	if MinKEKLen != 14 {
		t.Errorf("MinKEKLen = %d, want 14 (112 bits, the FIPS 140-3 HKDF minimum)", MinKEKLen)
	}
}

// TestInitialize_ShortKEKProvider_FailsClosed drives the production entry point
// with a provider that violates the 32-byte KEK contract: Initialize must
// return an error (never panic, in either FIPS mode) and leave the manager
// with no DEK, evidence-signing or audit-checkpoint key. Today the AES key-size
// check in the DEK wrap refuses such a KEK before the HKDF derivations run;
// this test fails if a future reordering lets a short KEK reach them without
// the MinKEKLen guard catching it.
func TestInitialize_ShortKEKProvider_FailsClosed(t *testing.T) {
	for _, n := range []int{0, 1, 13} {
		km := NewKeyManager(t.TempDir(), "dek.key", "kek.salt")
		km.SetKeyProvider(&mockKeyProvider{kek: kekGoldenPattern(n)})
		if err := km.Initialize(""); err == nil {
			t.Fatalf("%d-byte KEK: Initialize succeeded, want an error", n)
		}
		if _, _, ok := km.GetEvidenceSignKey(); ok {
			t.Errorf("%d-byte KEK: an evidence-signing key is set after a failed Initialize", n)
		}
		if _, _, ok := km.GetAuditCheckpointKey(); ok {
			t.Errorf("%d-byte KEK: an audit-checkpoint key is set after a failed Initialize", n)
		}
	}
}
