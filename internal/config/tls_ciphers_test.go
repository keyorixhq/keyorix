package config

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #333: when AllowedCiphers is empty/unset, ResolveCipherSuites must return the caller's
// default unchanged — an operator who never touched tls.allowed_ciphers must see no
// change in TLS posture.
func TestTLSConfig_ResolveCipherSuites_DefaultWhenUnset(t *testing.T) {
	def := []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}

	got, err := TLSConfig{}.ResolveCipherSuites(def)
	require.NoError(t, err)
	assert.Equal(t, def, got)
}

// #333: a configured, valid TLS 1.2 AEAD suite list must be resolved to the matching
// []uint16 IDs, in the order given, ignoring the caller's default entirely.
func TestTLSConfig_ResolveCipherSuites_HonorsConfiguredCiphers(t *testing.T) {
	def := []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}
	cfg := TLSConfig{AllowedCiphers: []string{
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
	}}

	got, err := cfg.ResolveCipherSuites(def)
	require.NoError(t, err)
	assert.Equal(t, []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}, got)
}

// #333: every entry in SecureCipherSuiteNames must resolve individually — sanity check
// that the allowlist and the resolver agree with each other.
func TestTLSConfig_ResolveCipherSuites_AllAllowlistedNamesResolve(t *testing.T) {
	for name, id := range SecureCipherSuiteNames {
		got, err := TLSConfig{AllowedCiphers: []string{name}}.ResolveCipherSuites(nil)
		require.NoErrorf(t, err, "name %q should resolve", name)
		assert.Equalf(t, []uint16{id}, got, "name %q", name)
	}
}

// #333: unrecognized, weak, or deprecated cipher suite names (RC4, 3DES, CBC-mode, plain
// typos, and TLS 1.3-only suite names — which don't apply to tls.Config.CipherSuites at
// all) must be rejected with an error rather than silently ignored or accepted.
func TestTLSConfig_ResolveCipherSuites_RejectsWeakOrUnknownCiphers(t *testing.T) {
	for _, name := range []string{
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_AES_128_GCM_SHA256", // TLS 1.3 suite name; not selectable via CipherSuites
		"not-a-real-cipher-suite",
		"",
	} {
		_, err := TLSConfig{AllowedCiphers: []string{name}}.ResolveCipherSuites(nil)
		assert.Errorf(t, err, "expected an error for cipher suite name %q", name)
	}
}

// A mix of one valid and one invalid name must still fail closed — a single bad entry
// must not be silently dropped while the rest is accepted.
func TestTLSConfig_ResolveCipherSuites_OneBadEntryFailsTheWholeList(t *testing.T) {
	cfg := TLSConfig{AllowedCiphers: []string{
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_RSA_WITH_RC4_128_SHA",
	}}
	_, err := cfg.ResolveCipherSuites(nil)
	assert.Error(t, err)
}
