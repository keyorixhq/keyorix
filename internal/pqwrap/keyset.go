package pqwrap

import (
	"errors"
)

// The keyset file (docs/design/pq-key-wrapping.md §7, option R) replaces the
// bare 60-byte wrapped DEK:
//
//	keyset  = header | slots | mac [32]
//	header  = "KXKS" [4] | version u8 (= 1) | dek_kcv [16] | slot count u8   (22 bytes)
//	slot    = type u8 | length u16 (big-endian) | body
//	  type 1, KEK slot:    kek_id [16] || AES-256-GCM(KEK, DEK), AAD = header || slot index
//	  type 2, hybrid slot: recipient public key || pqwrap envelope (purpose DEK, context = header)
//	dek_kcv = HKDF-SHA256(DEK, info "keyorix/pqwrap/v1/dek-kcv")[:16]
//	mac     = HMAC-SHA256(HKDF-SHA256(KEK, info "keyorix/pqwrap/v1/keyset-mac"), header || slots)
//
// Slot 0 is the KEK slot and every later slot is a hybrid slot, so one
// keyset has exactly one encoding.

// KeyFileFormat is the detected format of a wrapped-DEK file (§12).
type KeyFileFormat int

const (
	// FormatUnknown is refused, never guessed.
	FormatUnknown KeyFileFormat = iota
	// FormatLegacy60 is the pre-keyset dek.key: nonce(12) || ct(32) || tag(16)
	// under the KEK, no header, no AAD.
	FormatLegacy60
	// FormatKeysetV1 is the keyset above.
	FormatKeysetV1
)

func (f KeyFileFormat) String() string {
	switch f {
	case FormatLegacy60:
		return "legacy-60"
	case FormatKeysetV1:
		return "keyset-v1"
	}
	return "unknown"
}

const (
	// KeysetVersion is the only keyset version this package reads or writes.
	KeysetVersion = 1
	// LegacyKeyFileSize is the exact size of a legacy-60 key file.
	LegacyKeyFileSize = 60
	// DEKSize is the only DEK length a key file carries.
	DEKSize = 32
	// KEKIDSize is the length of the KEK slot's key id.
	KEKIDSize = 16
	// MaxRecipients bounds the hybrid slots in one keyset.
	MaxRecipients = 16
	// RecipientSuite is the write policy for hybrid (escrow and DR) slots:
	// long-lived offline recipients use ML-KEM-1024 (§7). Readers accept
	// every suite in the closed registry.
	RecipientSuite = SuiteX25519MLKEM1024
)

// Sentinel errors, so callers can say what failed without string matching.
var (
	// ErrUnknownFormat: neither legacy-60 nor a keyset.
	ErrUnknownFormat = errors.New("pqwrap: key file is neither legacy-60 nor keyset-v1")
	// ErrKeysetVersion: a keyset written by a newer binary.
	ErrKeysetVersion = errors.New("pqwrap: keyset version not supported by this binary")
	// ErrKeysetMalformed: the keyset does not parse.
	ErrKeysetMalformed = errors.New("pqwrap: keyset is malformed")
	// ErrKEKSlot: the KEK slot does not open under this KEK (wrong KEK, or
	// the header or slot was changed).
	ErrKEKSlot = errors.New("pqwrap: KEK slot does not open under this KEK")
	// ErrKeysetMAC: the keyset MAC does not verify under this KEK.
	ErrKeysetMAC = errors.New("pqwrap: keyset MAC does not verify")
	// ErrKCV: the unwrapped DEK does not match the header's key-check value.
	ErrKCV = errors.New("pqwrap: DEK does not match the keyset key-check value")
	// ErrLegacyOpen: a legacy-60 file does not open under this KEK.
	ErrLegacyOpen = errors.New("pqwrap: legacy key file does not open under this KEK")
)

var errNotImplemented = errors.New("pqwrap: keyset not implemented")

// Keyset is an opened keyset: the DEK, the KEK slot's key id and the hybrid
// recipients in slot order.
type Keyset struct {
	DEK        []byte
	KEKID      [KEKIDSize]byte
	Recipients []*PublicKey
}

// DetectFormat classifies a key file by its bytes alone. It runs no
// cryptography; a detected format is not yet authentic.
func DetectFormat(b []byte) KeyFileFormat { return FormatUnknown }

// SealKeyset builds a keyset for dek: a KEK slot under kek with kekID, and
// one hybrid slot per recipient, in order.
func SealKeyset(dek, kek []byte, kekID [KEKIDSize]byte, recipients []*PublicKey) ([]byte, error) {
	return nil, errNotImplemented
}

// OpenKeyset opens a keyset with kek: parse, KEK slot, MAC, KCV, then the
// structure of every hybrid slot.
func OpenKeyset(b, kek []byte) (*Keyset, error) { return nil, errNotImplemented }

// OpenKeyFile opens either format with kek and reports which it was.
func OpenKeyFile(b, kek []byte) (*Keyset, KeyFileFormat, error) {
	return nil, FormatUnknown, errNotImplemented
}

// SealLegacy writes a legacy-60 key file (rewrap --to legacy).
func SealLegacy(dek, kek []byte) ([]byte, error) { return nil, errNotImplemented }

// RekeyKeyset re-wraps the KEK slot under newKEK and recomputes the MAC,
// keeping every hybrid slot byte for byte (rotate-kek, migrate-provider).
func RekeyKeyset(b, oldKEK, newKEK []byte, newKEKID [KEKIDSize]byte) ([]byte, error) {
	return nil, errNotImplemented
}

// UnwrapRecipientSlot opens hybrid slot index (1-based slot position) with an
// escrow private key, without the KEK. The result is NOT authenticated (§6).
func UnwrapRecipientSlot(b []byte, index int, priv *PrivateKey) ([]byte, error) {
	return nil, errNotImplemented
}

// SameRecipients reports whether two opened keysets have the same hybrid
// recipients (key id and suite) in the same order.
func SameRecipients(a, b *Keyset) error { return errNotImplemented }
