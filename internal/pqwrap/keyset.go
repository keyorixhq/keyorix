package pqwrap

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
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
// keyset has exactly one encoding. The slot count is in the header, and the
// header is the KEK slot's AAD and every hybrid slot's context: dropping or
// adding a slot fails the KEK-slot unwrap before the MAC is even checked.
//
// Why the MAC: a pqwrap envelope proves nothing about who wrote it (§6), so a
// key-directory writer holding only public keys could otherwise substitute a
// DEK of their choice. Only a KEK holder can produce the MAC, and boot
// refuses a keyset whose MAC does not verify. The KCV is a consistency check
// for a slot that disagrees with its header, not an authenticator: an
// attacker who rewrites both can recompute it (TestKeyset_KCVIsNotOriginAuthentication).

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

const (
	keysetHeaderSize = 22
	keysetMACSize    = 32
	kcvSize          = 16
	slotHeaderSize   = 3 // type u8, length u16
	slotTypeKEK      = 1
	slotTypeHybrid   = 2
	kekSlotBodySize  = KEKIDSize + aeadOverhead + DEKSize

	offKSVersion = 4
	offKSKCV     = 5
	offKSCount   = 21

	kcvInfo       = "keyorix/pqwrap/v1/dek-kcv"
	keysetMACInfo = "keyorix/pqwrap/v1/keyset-mac"
)

var keysetMagic = [4]byte{'K', 'X', 'K', 'S'}

// Keyset is an opened keyset: the DEK, the KEK slot's key id and the hybrid
// recipients in slot order. A legacy-60 file opens to a Keyset with a zero
// KEKID and no recipients.
type Keyset struct {
	DEK        []byte
	KEKID      [KEKIDSize]byte
	Recipients []*PublicKey
}

// DetectFormat classifies a key file by its bytes alone. It runs no
// cryptography; a detected format is not yet authentic. A legacy file is
// exactly 60 bytes and starts with a random nonce, so length decides first:
// a keyset is never 60 bytes (the smallest is 22 + 3 + 76 + 32).
func DetectFormat(b []byte) KeyFileFormat {
	switch {
	case len(b) == LegacyKeyFileSize:
		return FormatLegacy60
	case len(b) > LegacyKeyFileSize && [4]byte(b[:4]) == keysetMagic && b[offKSVersion] == KeysetVersion:
		return FormatKeysetV1
	}
	return FormatUnknown
}

func kcv(dek []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, dek, nil, kcvInfo, kcvSize)
}

func keysetMAC(kek, signed []byte) ([]byte, error) {
	mk, err := hkdf.Key(sha256.New, kek, nil, keysetMACInfo, 32)
	if err != nil {
		return nil, err
	}
	defer clear(mk)
	h := hmac.New(sha256.New, mk)
	h.Write(signed)
	return h.Sum(nil), nil
}

func checkKey(name string, k []byte) error {
	if len(k) != 32 {
		return fmt.Errorf("pqwrap: %s must be 32 bytes, got %d", name, len(k))
	}
	if subtle.ConstantTimeCompare(k, make([]byte, 32)) == 1 {
		return fmt.Errorf("pqwrap: %s is all-zero bytes", name)
	}
	return nil
}

func hybridSlotSize(s Suite) (int, bool) {
	p, ok := suites[s]
	if !ok {
		return 0, false
	}
	return 2 + x25519Size + p.ekSize + EnvelopeSize(s, DEKSize), true
}

type hybridSlot struct {
	pub *PublicKey
	env []byte
}

// parsedKeyset is the strict structural parse of a keyset. A parsed keyset
// is not yet authentic: nothing here used the KEK.
type parsedKeyset struct {
	header  []byte
	kekID   [KEKIDSize]byte
	kekSeal []byte
	hybrid  []hybridSlot
	signed  []byte // header || slots, the MAC input
	mac     []byte
}

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrKeysetMalformed, fmt.Sprintf(format, a...))
}

// parseKeyset checks magic, version, the slot count, slot 0 being the only
// KEK slot, every slot length against its type and suite, every hybrid slot's
// public key and envelope (purpose DEK, suite and key id matching the stored
// key), no duplicate recipient, and no trailing bytes.
func parseKeyset(b []byte) (*parsedKeyset, error) {
	if len(b) < keysetHeaderSize+keysetMACSize || [4]byte(b[:4]) != keysetMagic {
		return nil, malformed("too short or no KXKS magic")
	}
	if v := b[offKSVersion]; v != KeysetVersion {
		return nil, fmt.Errorf("%w: keyset version %d, this binary reads %d", ErrKeysetVersion, v, KeysetVersion)
	}
	count := int(b[offKSCount])
	if count < 1 || count > 1+MaxRecipients {
		return nil, malformed("slot count %d out of range", count)
	}
	p := &parsedKeyset{
		header: bytes.Clone(b[:keysetHeaderSize]),
		signed: bytes.Clone(b[:len(b)-keysetMACSize]),
		mac:    bytes.Clone(b[len(b)-keysetMACSize:]),
	}
	rest := b[keysetHeaderSize : len(b)-keysetMACSize]
	seen := map[[keyIDSize]byte]bool{}
	for i := range count {
		if len(rest) < slotHeaderSize {
			return nil, malformed("slot %d truncated", i)
		}
		typ, n := rest[0], int(binary.BigEndian.Uint16(rest[1:3]))
		rest = rest[slotHeaderSize:]
		if len(rest) < n {
			return nil, malformed("slot %d truncated", i)
		}
		body := rest[:n]
		rest = rest[n:]
		if i == 0 {
			if typ != slotTypeKEK || n != kekSlotBodySize {
				return nil, malformed("slot 0 must be the KEK slot (%d bytes)", kekSlotBodySize)
			}
			p.kekID = [KEKIDSize]byte(body[:KEKIDSize])
			p.kekSeal = bytes.Clone(body[KEKIDSize:])
			continue
		}
		if typ != slotTypeHybrid || n < 2 {
			return nil, malformed("slot %d must be a hybrid slot", i)
		}
		s := Suite(binary.BigEndian.Uint16(body))
		want, ok := hybridSlotSize(s)
		if !ok || n != want {
			return nil, malformed("slot %d: suite %v or length %d not valid", i, s, n)
		}
		pkLen := 2 + x25519Size + suites[s].ekSize
		pub, err := ParsePublicKey(body[:pkLen])
		if err != nil {
			return nil, malformed("slot %d: recipient public key: %v", i, err)
		}
		env, err := ParseEnvelope(body[pkLen:])
		if err != nil {
			return nil, malformed("slot %d: envelope: %v", i, err)
		}
		if env.Purpose != PurposeDEK || env.Suite != s || env.KeyID != pub.KeyID() {
			return nil, malformed("slot %d: envelope does not match its recipient key (purpose %v, suite %v)", i, env.Purpose, env.Suite)
		}
		if seen[pub.KeyID()] {
			return nil, malformed("slot %d: duplicate recipient", i)
		}
		seen[pub.KeyID()] = true
		p.hybrid = append(p.hybrid, hybridSlot{pub: pub, env: bytes.Clone(body[pkLen:])})
	}
	if len(rest) != 0 {
		return nil, malformed("%d bytes after the last slot", len(rest))
	}
	return p, nil
}

func kekSlotAAD(header []byte) []byte {
	return append(bytes.Clone(header), 0) // slot index 0
}

func (p *parsedKeyset) openKEKSlot(kek []byte) ([]byte, error) {
	a, err := randomNonceGCM(kek)
	if err != nil {
		return nil, err
	}
	dek, err := a.Open(nil, nil, p.kekSeal, kekSlotAAD(p.header))
	if err != nil {
		return nil, ErrKEKSlot
	}
	return dek, nil
}

// OpenKeyset opens a keyset with kek, in the order §7 gives: parse, KEK
// slot, MAC, KCV. The hybrid slots' structure is checked by the parse.
func OpenKeyset(b, kek []byte) (*Keyset, error) {
	if err := checkKey("KEK", kek); err != nil {
		return nil, err
	}
	p, err := parseKeyset(b)
	if err != nil {
		return nil, err
	}
	dek, err := p.openKEKSlot(kek)
	if err != nil {
		return nil, err
	}
	mac, err := keysetMAC(kek, p.signed)
	if err != nil {
		clear(dek)
		return nil, err
	}
	if !hmac.Equal(mac, p.mac) {
		clear(dek)
		return nil, ErrKeysetMAC
	}
	sum, err := kcv(dek)
	if err != nil || !hmac.Equal(sum, p.header[offKSKCV:offKSKCV+kcvSize]) {
		clear(dek)
		return nil, ErrKCV
	}
	ks := &Keyset{DEK: dek, KEKID: p.kekID}
	for _, h := range p.hybrid {
		ks.Recipients = append(ks.Recipients, h.pub)
	}
	return ks, nil
}

// OpenKeyFile opens either format with kek and reports which it was. An
// unknown format and a keyset from a newer binary are refused.
func OpenKeyFile(b, kek []byte) (*Keyset, KeyFileFormat, error) {
	switch DetectFormat(b) {
	case FormatLegacy60:
		dek, err := openLegacy(b, kek)
		if err != nil {
			return nil, FormatUnknown, err
		}
		return &Keyset{DEK: dek}, FormatLegacy60, nil
	case FormatKeysetV1:
		ks, err := OpenKeyset(b, kek)
		if err != nil {
			return nil, FormatUnknown, err
		}
		return ks, FormatKeysetV1, nil
	}
	if len(b) > LegacyKeyFileSize && [4]byte(b[:4]) == keysetMagic {
		return nil, FormatUnknown, fmt.Errorf("%w: keyset version %d, this binary reads %d", ErrKeysetVersion, b[offKSVersion], KeysetVersion)
	}
	return nil, FormatUnknown, fmt.Errorf("%w (%d bytes)", ErrUnknownFormat, len(b))
}

func openLegacy(b, kek []byte) ([]byte, error) {
	if err := checkKey("KEK", kek); err != nil {
		return nil, err
	}
	// NewGCMWithRandomNonce reads the nonce from the first 12 bytes, which is
	// exactly the legacy layout nonce || ct || tag.
	a, err := randomNonceGCM(kek)
	if err != nil {
		return nil, err
	}
	dek, err := a.Open(nil, nil, b, nil)
	if err != nil || len(dek) != DEKSize {
		return nil, ErrLegacyOpen
	}
	return dek, nil
}

// SealLegacy writes a legacy-60 key file, for `rewrap --to legacy` only
// (§13). It drops every hybrid slot by construction.
func SealLegacy(dek, kek []byte) ([]byte, error) {
	if err := checkKey("DEK", dek); err != nil {
		return nil, err
	}
	if err := checkKey("KEK", kek); err != nil {
		return nil, err
	}
	a, err := randomNonceGCM(kek)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nil, dek, nil), nil // #nosec G407 -- the nil nonce is deliberate: NewGCMWithRandomNonce draws and prepends a fresh one
}

func newHeader(dek []byte, count int) ([]byte, error) {
	sum, err := kcv(dek)
	if err != nil {
		return nil, err
	}
	h := make([]byte, 0, keysetHeaderSize)
	h = append(h, keysetMagic[:]...)
	h = append(h, KeysetVersion)
	h = append(h, sum...)
	return append(h, byte(count)), nil // #nosec G115 -- count <= 1+MaxRecipients, checked by the callers
}

func appendSlot(out []byte, typ byte, body []byte) []byte {
	out = append(out, typ)
	out = binary.BigEndian.AppendUint16(out, uint16(len(body))) // #nosec G115 -- slot bodies are at most hybridSlotSize(1024) < 4 KiB
	return append(out, body...)
}

func sealKEKSlot(header, dek, kek []byte, kekID [KEKIDSize]byte) ([]byte, error) {
	a, err := randomNonceGCM(kek)
	if err != nil {
		return nil, err
	}
	return append(kekID[:], a.Seal(nil, nil, dek, kekSlotAAD(header))...), nil // #nosec G407 -- nil nonce: NewGCMWithRandomNonce draws a fresh one
}

func finish(signed, kek []byte) ([]byte, error) {
	mac, err := keysetMAC(kek, signed)
	if err != nil {
		return nil, err
	}
	return append(signed, mac...), nil
}

// SealKeyset builds a keyset for dek: a KEK slot under kek with kekID, and
// one hybrid slot per recipient, in the given order. Recipients must use
// RecipientSuite and be distinct. A DEK rotation passes the current keyset's
// Recipients, so every hybrid slot is re-wrapped to the new DEK in one file.
func SealKeyset(dek, kek []byte, kekID [KEKIDSize]byte, recipients []*PublicKey) ([]byte, error) {
	if err := checkKey("DEK", dek); err != nil {
		return nil, err
	}
	if err := checkKey("KEK", kek); err != nil {
		return nil, err
	}
	if len(recipients) > MaxRecipients {
		return nil, fmt.Errorf("pqwrap: %d recipients, at most %d", len(recipients), MaxRecipients)
	}
	seen := map[[keyIDSize]byte]bool{}
	for i, r := range recipients {
		if r == nil {
			return nil, fmt.Errorf("pqwrap: recipient %d is nil", i)
		}
		if r.suite != RecipientSuite {
			return nil, fmt.Errorf("pqwrap: recipient %d uses %v; keyset recipients use %v", i, r.suite, RecipientSuite)
		}
		if seen[r.id] {
			return nil, fmt.Errorf("pqwrap: recipient %d is a duplicate", i)
		}
		seen[r.id] = true
	}
	header, err := newHeader(dek, 1+len(recipients))
	if err != nil {
		return nil, err
	}
	kekSlot, err := sealKEKSlot(header, dek, kek, kekID)
	if err != nil {
		return nil, err
	}
	out := appendSlot(bytes.Clone(header), slotTypeKEK, kekSlot)
	for i, r := range recipients {
		env, err := Wrap(r, PurposeDEK, header, dek)
		if err != nil {
			return nil, fmt.Errorf("pqwrap: wrap to recipient %d: %w", i, err)
		}
		out = appendSlot(out, slotTypeHybrid, append(r.Bytes(), env...))
	}
	return finish(out, kek)
}

// RekeyKeyset re-wraps the KEK slot under newKEK with newKEKID and
// recomputes the MAC, keeping the header and every hybrid slot byte for byte
// (rotate-kek, migrate-provider: the DEK and the recipients did not change,
// §8). The result is opened under newKEK before it is returned.
func RekeyKeyset(b, oldKEK, newKEK []byte, newKEKID [KEKIDSize]byte) ([]byte, error) {
	if err := checkKey("new KEK", newKEK); err != nil {
		return nil, err
	}
	ks, err := OpenKeyset(b, oldKEK)
	if err != nil {
		return nil, err
	}
	defer clear(ks.DEK)
	p, err := parseKeyset(b)
	if err != nil {
		return nil, err
	}
	kekSlot, err := sealKEKSlot(p.header, ks.DEK, newKEK, newKEKID)
	if err != nil {
		return nil, err
	}
	out := appendSlot(bytes.Clone(p.header), slotTypeKEK, kekSlot)
	for _, h := range p.hybrid {
		out = appendSlot(out, slotTypeHybrid, append(h.pub.Bytes(), h.env...))
	}
	out, err = finish(out, newKEK)
	if err != nil {
		return nil, err
	}
	check, err := OpenKeyset(out, newKEK)
	if err != nil {
		return nil, fmt.Errorf("pqwrap: rekeyed keyset does not open: %w", err)
	}
	defer clear(check.DEK)
	if !hmac.Equal(check.DEK, ks.DEK) {
		return nil, errors.New("pqwrap: rekeyed keyset yields a different DEK")
	}
	return out, nil
}

// UnwrapRecipientSlot opens hybrid slot index (its slot position, 1..count-1)
// with an escrow private key, without the KEK. It checks the KCV, which
// catches a slot spliced under another header, but the result is NOT
// authenticated: without the KEK nothing proves who wrote the keyset (§6).
func UnwrapRecipientSlot(b []byte, index int, priv *PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("pqwrap: nil private key")
	}
	p, err := parseKeyset(b)
	if err != nil {
		return nil, err
	}
	if index < 1 || index > len(p.hybrid) {
		return nil, fmt.Errorf("pqwrap: no hybrid slot %d (keyset has %d)", index, len(p.hybrid))
	}
	h := p.hybrid[index-1]
	if h.pub.KeyID() != priv.PublicKey().KeyID() {
		return nil, fmt.Errorf("pqwrap: slot %d is for a different recipient", index)
	}
	dek, err := Unwrap(priv, PurposeDEK, p.header, h.env)
	if err != nil {
		return nil, err
	}
	sum, err := kcv(dek)
	if err != nil || len(dek) != DEKSize || !hmac.Equal(sum, p.header[offKSKCV:offKSKCV+kcvSize]) {
		clear(dek)
		return nil, ErrKCV
	}
	return dek, nil
}

// SameRecipients reports whether two opened keysets have the same hybrid
// recipients (key id and suite) in the same order: the pre-commit check of a
// DEK rotation and of the rewrap job (§7, §12).
func SameRecipients(a, b *Keyset) error {
	if len(a.Recipients) != len(b.Recipients) {
		return fmt.Errorf("pqwrap: %d recipients, expected %d", len(b.Recipients), len(a.Recipients))
	}
	for i := range a.Recipients {
		ra, rb := a.Recipients[i], b.Recipients[i]
		if ra.KeyID() != rb.KeyID() || ra.suite != rb.suite {
			return fmt.Errorf("pqwrap: recipient in slot %d differs (key id %x, expected %x)", i+1, rb.id, ra.id)
		}
	}
	return nil
}
