// Package pqwrap is the RD-PQWRAP-1 proof of concept for hybrid post-quantum
// key wrapping (docs/design/pq-key-wrapping.md). STUB: tests first.
package pqwrap

import (
	"crypto/cipher"
	"crypto/ecdh"
	"errors"
)

var errNotImplemented = errors.New("pqwrap: not implemented")

// Suite identifies one fixed algorithm combination.
type Suite uint16

const (
	SuiteX25519MLKEM768  Suite = 0x0001
	SuiteX25519MLKEM1024 Suite = 0x0002
)

// Purpose binds an envelope to what the wrapped key is for.
type Purpose uint8

const (
	PurposeDEK       Purpose = 0x01
	PurposeBackupKey Purpose = 0x02
)

const (
	Version    = 1
	SeedSize   = 96
	MaxKeySize = 64
)

type PublicKey struct {
	suite   Suite
	mlkemEK []byte
}
type PrivateKey struct{ suite Suite }

type Envelope struct {
	Version         uint8
	Suite           Suite
	Purpose         Purpose
	KeyID           [16]byte
	X25519Ephemeral []byte
	MLKEMCiphertext []byte
	Sealed          []byte
}

func NewPrivateKeyFromSeed(s Suite, seed []byte) (*PrivateKey, error) { return nil, errNotImplemented }
func GenerateKey(s Suite) (*PrivateKey, error)                       { return nil, errNotImplemented }
func (k *PrivateKey) PublicKey() *PublicKey                           { return nil }
func (p *PublicKey) Bytes() []byte                                    { return nil }
func (p *PublicKey) KeyID() [16]byte                                  { return [16]byte{} }
func ParsePublicKey(b []byte) (*PublicKey, error)                     { return nil, errNotImplemented }
func DeriveSeed(kek []byte, s Suite, keyEpoch string) ([]byte, error) { return nil, errNotImplemented }
func Wrap(pub *PublicKey, p Purpose, context, key []byte) ([]byte, error) {
	return nil, errNotImplemented
}
func Unwrap(priv *PrivateKey, p Purpose, context, envelope []byte) ([]byte, error) {
	return nil, errNotImplemented
}
func ParseEnvelope(b []byte) (*Envelope, error) { return nil, errNotImplemented }
func (e *Envelope) Marshal() []byte             { return nil }
func EnvelopeSize(s Suite, keyLen int) int      { return 0 }

const (
	offVersion   = 4
	offSuite     = 5
	offPurpose   = 7
	offKeyID     = 8
	aeadOverhead = 28
)

func (s Suite) String() string  { return "" }
func (p Purpose) String() string { return "" }

type encapsulation struct {
	ssM, ctM []byte
	xEph     *ecdh.PrivateKey
}

func seal(pub *PublicKey, p Purpose, context, key []byte, enc encapsulation, newAEAD func([]byte) (cipher.AEAD, error)) (env, ssX, th, wk []byte, err error) {
	return nil, nil, nil, nil, errNotImplemented
}
