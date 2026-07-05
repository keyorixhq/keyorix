package grpc

import (
	"crypto/tls"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// #172: gRPC AutoCert mode must not silently discard the hardened
// MinVersion/CipherSuites — createGRPCTLSConfig must apply the same hardening on the
// AutoCert branch as it does on the non-AutoCert (manual cert/key) branch below.
func TestCreateGRPCTLSConfig_AutoCertAppliesHardening(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true
	cfg.Server.GRPC.TLS.AutoCert = true

	tlsConfig, err := createGRPCTLSConfig(cfg)
	if err != nil {
		t.Fatalf("createGRPCTLSConfig: %v", err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want tls.VersionTLS12", tlsConfig.MinVersion)
	}
	if len(tlsConfig.CipherSuites) == 0 {
		t.Fatal("CipherSuites must not be empty on the AutoCert branch")
	}
}

// #333: when tls.allowed_ciphers is unset, createGRPCTLSConfig must keep the existing
// hardcoded secure default CipherSuites unchanged (no regression).
func TestCreateGRPCTLSConfig_DefaultPreservedWhenAllowedCiphersUnset(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true
	cfg.Server.GRPC.TLS.AutoCert = true

	tlsConfig, err := createGRPCTLSConfig(cfg)
	if err != nil {
		t.Fatalf("createGRPCTLSConfig: %v", err)
	}
	if !grpcCipherSuitesEqual(tlsConfig.CipherSuites, hardenedCipherSuites) {
		t.Errorf("CipherSuites = %v, want the unchanged hardcoded default %v", tlsConfig.CipherSuites, hardenedCipherSuites)
	}
}

// #333: when tls.allowed_ciphers names a valid, specific TLS 1.2 AEAD suite list, the
// resulting tls.Config must reflect exactly that list, not the hardcoded default.
func TestCreateGRPCTLSConfig_HonorsConfiguredAllowedCiphers(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true
	cfg.Server.GRPC.TLS.AutoCert = true
	cfg.Server.GRPC.TLS.AllowedCiphers = []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}
	want := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

	tlsConfig, err := createGRPCTLSConfig(cfg)
	if err != nil {
		t.Fatalf("createGRPCTLSConfig: %v", err)
	}
	if !grpcCipherSuitesEqual(tlsConfig.CipherSuites, want) {
		t.Errorf("CipherSuites = %v, want the configured %v (not the hardcoded default %v)", tlsConfig.CipherSuites, want, hardenedCipherSuites)
	}
}

// #333: an invalid/weak/deprecated cipher suite name must be rejected, not silently
// accepted, by createGRPCTLSConfig.
func TestCreateGRPCTLSConfig_RejectsWeakOrUnknownCipher(t *testing.T) {
	for _, name := range []string{
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"not-a-real-cipher-suite",
	} {
		cfg := &config.Config{}
		cfg.Server.GRPC.TLS.Enabled = true
		cfg.Server.GRPC.TLS.AutoCert = true
		cfg.Server.GRPC.TLS.AllowedCiphers = []string{name}

		if _, err := createGRPCTLSConfig(cfg); err == nil {
			t.Errorf("createGRPCTLSConfig must reject weak/unknown cipher suite %q", name)
		}
	}
}

// grpcCipherSuitesEqual reports whether two ordered cipher-suite ID slices are identical.
func grpcCipherSuitesEqual(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
