// Package crypto defines KeyProvider — the pluggable source of the 32-byte
// key-encryption key (KEK) that the encryption subsystem uses to wrap/unwrap the
// data-encryption key (DEK). Abstracting the KEK source lets a deployment choose
// how the KEK is obtained: derived from a passphrase (the default, unchanged), or
// supplied as raw key material from a file or environment variable (e.g. injected
// by a KMS, a sealed/SOPS secret, or a CSI driver). KMS/TPM-backed providers are a
// future Tier-2 follow-up that implement this same interface.
//
// A KeyProvider only SOURCES the KEK; wrapping/unwrapping the DEK with it stays in
// the encryption package, so providers carry no dependency on the cipher code.
package crypto

import "fmt"

// KEKSize is the required key-encryption-key length in bytes (AES-256).
const KEKSize = 32

// KeyProvider sources the 32-byte KEK. Implementations must return exactly
// KEKSize bytes. The caller owns the returned slice and wipes it after use.
type KeyProvider interface {
	// KEK returns the key-encryption key. It may have side effects on first use
	// (e.g. the password provider generates and persists a salt) but must be
	// deterministic thereafter for a given configuration.
	KEK() ([]byte, error)
	// Name identifies the provider kind for logging and key-version metadata.
	Name() string
}

// validateKEK ensures key material is exactly KEKSize bytes and is not the all-zero
// key — a shared guard so every provider rejects bad material with the same clear
// error. An all-zero KEK is a plausible empty-state (a zeroed/placeholder mounted
// secret, an unset env var read as zeros) and must never be accepted as real AES-256
// key material on a secrets product.
func validateKEK(key []byte, providerName string) ([]byte, error) {
	if len(key) != KEKSize {
		return nil, fmt.Errorf("%s key provider: KEK must be %d bytes, got %d", providerName, KEKSize, len(key))
	}
	var anySet byte
	for _, b := range key {
		anySet |= b
	}
	if anySet == 0 {
		return nil, fmt.Errorf("%s key provider: KEK is all-zero bytes — refusing placeholder/zeroed key material", providerName)
	}
	return key, nil
}
