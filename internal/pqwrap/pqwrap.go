// Package pqwrap is the RD-PQWRAP-1 proof of concept for hybrid post-quantum
// key wrapping: a KEM-DEM envelope that wraps a short symmetric key (a DEK or
// a backup content key) to an X25519 + ML-KEM public key. The design, the
// combiner rationale and the open decisions are in
// docs/design/pq-key-wrapping.md; section numbers below refer to it.
//
// STATUS: unwired research code. Nothing in the server, the CLI or the key
// paths imports this package, and the design note is not yet accepted. Do not
// wire it in before the ADR is approved.
//
// The construction (§4):
//
//	ss_M, ct_M = ML-KEM.Encaps(ek_M)                 FIPS 203
//	ss_X       = X25519(eph, pk_X), ct_X = eph·G     RFC 7748
//	th         = SHA-256(transcriptLabel || header || ct_X || ct_M || pk_X || ek_M)
//	PRK        = HKDF-Extract(salt = extractSalt, IKM = ss_M || ss_X)
//	wk         = HKDF-Expand(PRK, info = suiteLabel || 0x00 || th, 32)
//	sealed     = AES-256-GCM(wk, random nonce).Seal(key, aad = header || context)
//
// Both shared secrets enter the KDF and both ciphertexts (and both public
// keys) enter the transcript, so the wrap key stays secret while either
// component holds (a concatenation, "GHP"-style combiner). ML-KEM's secret
// comes first: under SP 800-56C Rev. 2 it is the approved shared secret Z and
// the X25519 secret is the auxiliary T appended to it.
//
// The format is fixed per Suite: there is no negotiation and no runtime
// algorithm choice. Adding an algorithm means a new Suite constant (or a new
// Version) in a reviewed change, never a configuration value (§5).
package pqwrap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/fips140"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Suite identifies one fixed algorithm combination. Every length in an
// envelope follows from its Suite.
type Suite uint16

const (
	// SuiteX25519MLKEM768 is the default: X25519 + ML-KEM-768, HKDF-SHA-256,
	// AES-256-GCM.
	SuiteX25519MLKEM768 Suite = 0x0001
	// SuiteX25519MLKEM1024 is for long-lived data (backups, archives): X25519
	// + ML-KEM-1024, HKDF-SHA-256, AES-256-GCM.
	SuiteX25519MLKEM1024 Suite = 0x0002
)

// Purpose binds an envelope to what the wrapped key is for. A reader states
// the purpose it expects; an envelope written for another purpose fails.
type Purpose uint8

const (
	PurposeDEK       Purpose = 0x01
	PurposeBackupKey Purpose = 0x02
)

const (
	// Version is the only envelope version this package reads or writes.
	Version = 1
	// SeedSize is the private-key seed: the 64-byte ML-KEM seed (d || z,
	// FIPS 203) followed by the 32-byte X25519 private scalar.
	SeedSize = mlkem.SeedSize + x25519Size
	// MaxKeySize bounds the wrapped key. This is a key wrap, not a general
	// encryption format.
	MaxKeySize = 64
)

// Context strings (§4). Changing any of them is a format change.
const (
	extractSalt     = "keyorix/pqwrap/v1/extract"
	transcriptLabel = "keyorix/pqwrap/v1/transcript"
	keyIDLabel      = "keyorix/pqwrap/v1/keyid"
	seedLabel       = "keyorix/pqwrap/v1/key-seed"
)

const (
	x25519Size   = 32
	keyIDSize    = 16
	headerSize   = 24 // magic(4) version(1) suite(2) purpose(1) key id(16)
	lenFieldSize = 2
	aeadOverhead = 12 + 16 // GCM random nonce + tag

	offVersion = 4
	offSuite   = 5
	offPurpose = 7
	offKeyID   = 8
)

var magic = [4]byte{'K', 'X', 'P', 'W'}

type suiteParams struct {
	label  string
	ekSize int
	ctSize int
}

var suites = map[Suite]suiteParams{
	SuiteX25519MLKEM768: {
		label:  "keyorix/pqwrap/v1/X25519-MLKEM768/HKDF-SHA256/AES-256-GCM",
		ekSize: mlkem.EncapsulationKeySize768,
		ctSize: mlkem.CiphertextSize768,
	},
	SuiteX25519MLKEM1024: {
		label:  "keyorix/pqwrap/v1/X25519-MLKEM1024/HKDF-SHA256/AES-256-GCM",
		ekSize: mlkem.EncapsulationKeySize1024,
		ctSize: mlkem.CiphertextSize1024,
	},
}

func (s Suite) String() string {
	switch s {
	case SuiteX25519MLKEM768:
		return "X25519-MLKEM768"
	case SuiteX25519MLKEM1024:
		return "X25519-MLKEM1024"
	}
	return fmt.Sprintf("Suite(%#04x)", uint16(s))
}

func (p Purpose) String() string {
	switch p {
	case PurposeDEK:
		return "dek"
	case PurposeBackupKey:
		return "backup-key"
	}
	return fmt.Sprintf("Purpose(%#02x)", uint8(p))
}

func (p Purpose) known() bool { return p == PurposeDEK || p == PurposeBackupKey }

// errUnwrap is the single error for every cryptographic failure in Unwrap,
// so a caller learns nothing about which check failed.
var errUnwrap = errors.New("pqwrap: envelope does not authenticate under this key and context")

// withoutX25519Enforcement runs f with GODEBUG=fips140=only enforcement
// lifted. X25519 is not an approved algorithm, but here it only contributes
// the auxiliary secret of a hybrid whose approved component is ML-KEM
// (SP 800-56C Rev. 2, SP 800-227). crypto/hpke's MLKEM768-X25519 does the
// same. Keep every call tightly scoped to one X25519 operation.
func withoutX25519Enforcement(f func()) { fips140.WithoutEnforcement(f) }

// PublicKey is a recipient's encapsulation key: an X25519 public key and an
// ML-KEM encapsulation key of the suite's parameter set.
type PublicKey struct {
	suite   Suite
	x       *ecdh.PublicKey
	mlkemEK []byte
	id      [keyIDSize]byte
}

// PrivateKey is a recipient's decapsulation key, built from a SeedSize seed.
type PrivateKey struct {
	suite  Suite
	dk768  *mlkem.DecapsulationKey768
	dk1024 *mlkem.DecapsulationKey1024
	x      *ecdh.PrivateKey
	public *PublicKey
}

// NewPrivateKeyFromSeed builds a private key deterministically from seed
// (SeedSize bytes: ML-KEM seed, then X25519 scalar).
func NewPrivateKeyFromSeed(s Suite, seed []byte) (*PrivateKey, error) {
	if _, ok := suites[s]; !ok {
		return nil, fmt.Errorf("pqwrap: unknown suite %v", s)
	}
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("pqwrap: seed must be %d bytes, got %d", SeedSize, len(seed))
	}
	k := &PrivateKey{suite: s}
	var ek []byte
	var err error
	switch s {
	case SuiteX25519MLKEM768:
		if k.dk768, err = mlkem.NewDecapsulationKey768(seed[:mlkem.SeedSize]); err == nil {
			ek = k.dk768.EncapsulationKey().Bytes()
		}
	case SuiteX25519MLKEM1024:
		if k.dk1024, err = mlkem.NewDecapsulationKey1024(seed[:mlkem.SeedSize]); err == nil {
			ek = k.dk1024.EncapsulationKey().Bytes()
		}
	}
	if err != nil {
		return nil, fmt.Errorf("pqwrap: ML-KEM key from seed: %w", err)
	}
	withoutX25519Enforcement(func() { k.x, err = ecdh.X25519().NewPrivateKey(seed[mlkem.SeedSize:]) })
	if err != nil {
		return nil, fmt.Errorf("pqwrap: X25519 key from seed: %w", err)
	}
	k.public = newPublicKey(s, k.x.PublicKey(), ek)
	return k, nil
}

// GenerateKey returns a private key from a fresh random seed.
func GenerateKey(s Suite) (*PrivateKey, error) {
	seed := make([]byte, SeedSize)
	defer clear(seed)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("pqwrap: read seed: %w", err)
	}
	return NewPrivateKeyFromSeed(s, seed)
}

// DeriveSeed derives a private-key seed from a 32-byte KEK, for the design
// option where the install's wrapping key pair follows the KEK (§7, option
// K). keyEpoch separates successive key pairs under one KEK.
func DeriveSeed(kek []byte, s Suite, keyEpoch string) ([]byte, error) {
	p, ok := suites[s]
	if !ok {
		return nil, fmt.Errorf("pqwrap: unknown suite %v", s)
	}
	if len(kek) != 32 {
		return nil, fmt.Errorf("pqwrap: KEK must be 32 bytes, got %d", len(kek))
	}
	var set byte
	for _, b := range kek {
		set |= b
	}
	if set == 0 {
		return nil, errors.New("pqwrap: KEK is all-zero bytes")
	}
	return hkdf.Key(sha256.New, kek, []byte(extractSalt), seedLabel+"\x00"+p.label+"\x00"+keyEpoch, SeedSize)
}

// PublicKey returns the key's public half.
func (k *PrivateKey) PublicKey() *PublicKey { return k.public }

func newPublicKey(s Suite, x *ecdh.PublicKey, ek []byte) *PublicKey {
	p := &PublicKey{suite: s, x: x, mlkemEK: ek}
	h := sha256.New()
	h.Write([]byte(keyIDLabel + "\x00"))
	h.Write(p.Bytes())
	copy(p.id[:], h.Sum(nil))
	return p
}

// Bytes encodes the public key as suite(2) || X25519(32) || ML-KEM ek.
func (p *PublicKey) Bytes() []byte {
	out := binary.BigEndian.AppendUint16(nil, uint16(p.suite))
	out = append(out, p.x.Bytes()...)
	return append(out, p.mlkemEK...)
}

// KeyID is a 16-byte fingerprint of the public key, carried in every
// envelope so a reader can tell which key an envelope is for.
func (p *PublicKey) KeyID() [16]byte { return p.id }

// ParsePublicKey decodes Bytes' encoding, checking the suite and that both
// component keys are valid.
func ParsePublicKey(b []byte) (*PublicKey, error) {
	if len(b) < 2 {
		return nil, errors.New("pqwrap: public key too short")
	}
	s := Suite(binary.BigEndian.Uint16(b))
	params, ok := suites[s]
	if !ok {
		return nil, fmt.Errorf("pqwrap: unknown suite %v", s)
	}
	if len(b) != 2+x25519Size+params.ekSize {
		return nil, fmt.Errorf("pqwrap: %v public key must be %d bytes, got %d", s, 2+x25519Size+params.ekSize, len(b))
	}
	ek := b[2+x25519Size:]
	var err error
	switch s {
	case SuiteX25519MLKEM768:
		_, err = mlkem.NewEncapsulationKey768(ek)
	case SuiteX25519MLKEM1024:
		_, err = mlkem.NewEncapsulationKey1024(ek)
	}
	if err != nil {
		return nil, fmt.Errorf("pqwrap: invalid ML-KEM encapsulation key: %w", err)
	}
	var x *ecdh.PublicKey
	withoutX25519Enforcement(func() { x, err = ecdh.X25519().NewPublicKey(b[2 : 2+x25519Size]) })
	if err != nil {
		return nil, fmt.Errorf("pqwrap: invalid X25519 public key: %w", err)
	}
	return newPublicKey(s, x, bytes.Clone(ek)), nil
}

// Envelope is the parsed wire form (§5):
//
//	magic "KXPW" | version u8 | suite u16 | purpose u8 | key id [16]
//	| X25519 ephemeral [32] | ML-KEM ciphertext [suite] | sealed len u16 | sealed
//
// Integers are big-endian; sealed is nonce(12) || ciphertext || tag(16).
type Envelope struct {
	Version         uint8
	Suite           Suite
	Purpose         Purpose
	KeyID           [16]byte
	X25519Ephemeral []byte
	MLKEMCiphertext []byte
	Sealed          []byte
}

// EnvelopeSize is the encoded size of an envelope wrapping a keyLen-byte key,
// or 0 for an unknown suite.
func EnvelopeSize(s Suite, keyLen int) int {
	p, ok := suites[s]
	if !ok {
		return 0
	}
	return headerSize + x25519Size + p.ctSize + lenFieldSize + aeadOverhead + keyLen
}

func (e *Envelope) header() []byte {
	h := make([]byte, 0, headerSize)
	h = append(h, magic[:]...)
	h = append(h, e.Version)
	h = binary.BigEndian.AppendUint16(h, uint16(e.Suite))
	h = append(h, byte(e.Purpose))
	return append(h, e.KeyID[:]...)
}

// Marshal encodes e. It does not validate; ParseEnvelope does.
func (e *Envelope) Marshal() []byte {
	out := e.header()
	out = append(out, e.X25519Ephemeral...)
	out = append(out, e.MLKEMCiphertext...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(e.Sealed))) // #nosec G115 -- Wrap bounds the key to MaxKeySize, so len(Sealed) <= aeadOverhead+MaxKeySize (92); ParseEnvelope rejects anything longer
	return append(out, e.Sealed...)
}

// ParseEnvelope decodes and structurally validates an envelope: magic,
// version, a known suite and purpose, exact component lengths for the suite,
// a sealed length within bounds, and no trailing bytes. It runs no
// cryptography; a parsed envelope is not yet authentic.
func ParseEnvelope(b []byte) (*Envelope, error) {
	if len(b) < headerSize {
		return nil, errors.New("pqwrap: envelope shorter than its header")
	}
	if [4]byte(b[:4]) != magic {
		return nil, errors.New("pqwrap: not a pqwrap envelope")
	}
	e := &Envelope{
		Version: b[offVersion],
		Suite:   Suite(binary.BigEndian.Uint16(b[offSuite:])),
		Purpose: Purpose(b[offPurpose]),
		KeyID:   [16]byte(b[offKeyID:headerSize]),
	}
	if e.Version != Version {
		return nil, fmt.Errorf("pqwrap: unsupported envelope version %d", e.Version)
	}
	params, ok := suites[e.Suite]
	if !ok {
		return nil, fmt.Errorf("pqwrap: unknown suite %v", e.Suite)
	}
	if !e.Purpose.known() {
		return nil, fmt.Errorf("pqwrap: unknown purpose %v", e.Purpose)
	}
	rest := b[headerSize:]
	if len(rest) < x25519Size+params.ctSize+lenFieldSize {
		return nil, errors.New("pqwrap: envelope truncated")
	}
	e.X25519Ephemeral = bytes.Clone(rest[:x25519Size])
	rest = rest[x25519Size:]
	e.MLKEMCiphertext = bytes.Clone(rest[:params.ctSize])
	rest = rest[params.ctSize:]
	n := int(binary.BigEndian.Uint16(rest))
	rest = rest[lenFieldSize:]
	if n <= aeadOverhead || n > aeadOverhead+MaxKeySize {
		return nil, fmt.Errorf("pqwrap: sealed key length %d out of range", n)
	}
	if len(rest) != n {
		return nil, fmt.Errorf("pqwrap: sealed key is %d bytes, header says %d", len(rest), n)
	}
	e.Sealed = bytes.Clone(rest)
	return e, nil
}

// deriveWrapKey is the combiner (§4). Every input has a length fixed by the
// suite, and the suite is in the header, which comes first, so the plain
// concatenation in the transcript is unambiguous.
func deriveWrapKey(header, ctX, ctM []byte, pub *PublicKey, ssM, ssX []byte) (wk, th []byte, err error) {
	h := sha256.New()
	h.Write([]byte(transcriptLabel + "\x00"))
	h.Write(header)
	h.Write(ctX)
	h.Write(ctM)
	h.Write(pub.x.Bytes())
	h.Write(pub.mlkemEK)
	th = h.Sum(nil)

	ikm := make([]byte, 0, len(ssM)+len(ssX))
	ikm = append(append(ikm, ssM...), ssX...)
	defer clear(ikm)
	prk, err := hkdf.Extract(sha256.New, ikm, []byte(extractSalt))
	if err != nil {
		return nil, nil, err
	}
	defer clear(prk)
	wk, err = hkdf.Expand(sha256.New, prk, suites[pub.suite].label+"\x00"+string(th), 32)
	return wk, th, err
}

func aad(header, context []byte) []byte {
	return append(append(make([]byte, 0, len(header)+len(context)), header...), context...)
}

func randomNonceGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(b)
}

// encapsulation is the randomness of one wrap: drawn fresh by Wrap, fixed by
// the known-answer vectors.
type encapsulation struct {
	ssM, ctM []byte
	xEph     *ecdh.PrivateKey
}

// seal builds an envelope from one encapsulation. It returns the X25519
// shared secret, transcript hash and wrap key as well, for the vectors.
func seal(pub *PublicKey, p Purpose, context, key []byte, enc encapsulation, newAEAD func([]byte) (cipher.AEAD, error)) (env, ssX, th, wk []byte, err error) {
	e := &Envelope{Version: Version, Suite: pub.suite, Purpose: p, KeyID: pub.id, MLKEMCiphertext: enc.ctM}
	e.X25519Ephemeral = enc.xEph.PublicKey().Bytes()
	withoutX25519Enforcement(func() { ssX, err = enc.xEph.ECDH(pub.x) })
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("pqwrap: X25519: %w", err)
	}
	header := e.header()
	wk, th, err = deriveWrapKey(header, e.X25519Ephemeral, e.MLKEMCiphertext, pub, enc.ssM, ssX)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("pqwrap: derive wrap key: %w", err)
	}
	a, err := newAEAD(wk)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("pqwrap: AEAD: %w", err)
	}
	e.Sealed = a.Seal(nil, nil, key, aad(header, context)) // #nosec G407 -- the nil nonce is deliberate: newAEAD supplies the nonce (Wrap passes randomNonceGCM, which draws a fresh one and prepends it; only the known-answer vectors fix it)
	return e.Marshal(), ssX, th, wk, nil
}

// Wrap wraps key (1..MaxKeySize bytes) to pub for purpose p. context is bound
// as additional data and must be supplied again, unchanged, to Unwrap; it is
// where the caller names the envelope's place (install, epoch, archive id).
// Anyone holding pub can call Wrap: an envelope proves nothing about who
// wrote it (§6).
func Wrap(pub *PublicKey, p Purpose, context, key []byte) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("pqwrap: nil public key")
	}
	if !p.known() {
		return nil, fmt.Errorf("pqwrap: unknown purpose %v", p)
	}
	if len(key) == 0 || len(key) > MaxKeySize {
		return nil, fmt.Errorf("pqwrap: key must be 1..%d bytes, got %d", MaxKeySize, len(key))
	}
	var enc encapsulation
	switch pub.suite {
	case SuiteX25519MLKEM768:
		ek, err := mlkem.NewEncapsulationKey768(pub.mlkemEK)
		if err != nil {
			return nil, err
		}
		enc.ssM, enc.ctM = ek.Encapsulate()
	case SuiteX25519MLKEM1024:
		ek, err := mlkem.NewEncapsulationKey1024(pub.mlkemEK)
		if err != nil {
			return nil, err
		}
		enc.ssM, enc.ctM = ek.Encapsulate()
	default:
		return nil, fmt.Errorf("pqwrap: unknown suite %v", pub.suite)
	}
	defer clear(enc.ssM)
	var err error
	withoutX25519Enforcement(func() { enc.xEph, err = ecdh.X25519().GenerateKey(rand.Reader) })
	if err != nil {
		return nil, fmt.Errorf("pqwrap: X25519 ephemeral: %w", err)
	}
	env, ssX, _, wk, err := seal(pub, p, context, key, enc, randomNonceGCM)
	clear(ssX)
	clear(wk)
	return env, err
}

// Unwrap opens an envelope with priv, for expected purpose p and the same
// context Wrap was given. Structural problems get a descriptive error; every
// cryptographic failure gets the same one.
func Unwrap(priv *PrivateKey, p Purpose, context, envelope []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("pqwrap: nil private key")
	}
	e, err := ParseEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	if e.Suite != priv.suite {
		return nil, fmt.Errorf("pqwrap: envelope suite %v, key suite %v", e.Suite, priv.suite)
	}
	if e.Purpose != p {
		return nil, fmt.Errorf("pqwrap: envelope purpose %v, expected %v", e.Purpose, p)
	}
	if e.KeyID != priv.public.id {
		return nil, errors.New("pqwrap: envelope is for a different key")
	}
	var ssM []byte
	switch priv.suite {
	case SuiteX25519MLKEM768:
		ssM, err = priv.dk768.Decapsulate(e.MLKEMCiphertext)
	case SuiteX25519MLKEM1024:
		ssM, err = priv.dk1024.Decapsulate(e.MLKEMCiphertext)
	}
	if err != nil {
		return nil, errUnwrap
	}
	defer clear(ssM)
	var ssX []byte
	withoutX25519Enforcement(func() {
		var peer *ecdh.PublicKey
		if peer, err = ecdh.X25519().NewPublicKey(e.X25519Ephemeral); err == nil {
			ssX, err = priv.x.ECDH(peer)
		}
	})
	if err != nil {
		return nil, errUnwrap
	}
	defer clear(ssX)
	header := e.header()
	wk, _, err := deriveWrapKey(header, e.X25519Ephemeral, e.MLKEMCiphertext, priv.public, ssM, ssX)
	if err != nil {
		return nil, errUnwrap
	}
	defer clear(wk)
	a, err := randomNonceGCM(wk)
	if err != nil {
		return nil, errUnwrap
	}
	key, err := a.Open(nil, nil, e.Sealed, aad(header, context))
	if err != nil {
		return nil, errUnwrap
	}
	return key, nil
}
