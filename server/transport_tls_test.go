package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// writeSelfSignedCert generates a throwaway self-signed cert/key pair under dir and
// returns their paths, for exercising the non-AutoCert TLS config-building path
// without a real CA.
func writeSelfSignedCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	certOut, err := os.Create(certFile) // #nosec G304 -- test-only temp dir
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	defer certOut.Close() //nolint:errcheck
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) // #nosec G304 -- test-only temp dir
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	defer keyOut.Close() //nolint:errcheck
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
	return certFile, keyFile
}

// A group/world-readable key file must fail closed when the permission check is enabled,
// warn (no error) by default, and be allowed when explicitly overridden. A 0600 file or a
// missing file (first boot) passes.
func TestEnforceKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	dek := filepath.Join(dir, "dek.key")
	salt := filepath.Join(dir, "kek.salt")
	mk := func(p string, mode os.FileMode) {
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // defeat umask
			t.Fatal(err)
		}
	}

	base := func() *config.Config {
		c := &config.Config{}
		c.Storage.Encryption.Enabled = true
		c.Storage.Encryption.DEKPath = dek
		c.Storage.Encryption.SaltPath = salt
		return c
	}

	// 0600 files → ok regardless of the flag.
	mk(dek, 0600)
	mk(salt, 0600)
	if err := enforceKeyFilePermissions(base()); err != nil {
		t.Errorf("0600 key files must pass: %v", err)
	}

	// World-readable DEK + strict check → fail closed.
	mk(dek, 0644)
	strict := base()
	strict.Security.EnableFilePermissionCheck = true
	if err := enforceKeyFilePermissions(strict); err == nil {
		t.Error("world-readable key with enable_file_permission_check must fail closed")
	}

	// Same file, default (no strict flag) → warn only, no error.
	if err := enforceKeyFilePermissions(base()); err != nil {
		t.Errorf("default mode must warn, not fail: %v", err)
	}

	// Strict but explicitly overridden → allowed.
	override := base()
	override.Security.EnableFilePermissionCheck = true
	override.Security.AllowUnsafeFilePermissions = true
	if err := enforceKeyFilePermissions(override); err != nil {
		t.Errorf("allow_unsafe_file_permissions must override: %v", err)
	}
}

func cfgWith(httpEnabled, httpTLS, grpcEnabled, grpcTLS, require bool) *config.Config {
	c := &config.Config{}
	c.Server.HTTP.Enabled = httpEnabled
	c.Server.HTTP.TLS.Enabled = httpTLS
	c.Server.GRPC.Enabled = grpcEnabled
	c.Server.GRPC.TLS.Enabled = grpcTLS
	c.Security.RequireTransportTLS = require
	return c
}

func TestCheckTransportTLSPosture(t *testing.T) {
	// require_transport_tls + a cleartext enabled listener → fail closed.
	if err := checkTransportTLSPosture(cfgWith(true, false, false, false, true)); err == nil {
		t.Error("expected failure: HTTP cleartext with require_transport_tls set")
	}
	if err := checkTransportTLSPosture(cfgWith(false, false, true, false, true)); err == nil {
		t.Error("expected failure: gRPC cleartext with require_transport_tls set")
	}
	// require set but both listeners have TLS → ok.
	if err := checkTransportTLSPosture(cfgWith(true, true, true, true, true)); err != nil {
		t.Errorf("TLS on both listeners must pass even with require set: %v", err)
	}
	// require OFF + cleartext → no error (warns only).
	if err := checkTransportTLSPosture(cfgWith(true, false, true, false, false)); err != nil {
		t.Errorf("cleartext without require must not fail: %v", err)
	}
	// a disabled listener is ignored even under require.
	if err := checkTransportTLSPosture(cfgWith(false, false, false, false, true)); err != nil {
		t.Errorf("no enabled listeners must pass: %v", err)
	}
}

// #333: TLSConfig.AllowedCiphers is now wired into the HTTP/gRPC CipherSuites
// (server/main.go's applyTLSHardening, server/grpc/server.go's applyTLSHardening) — an
// operator who sets a valid TLS 1.2 AEAD suite name gets it honored; a bad
// (unrecognized/weak/deprecated) suite name fails closed at startup instead of being
// silently ignored (the old behavior) or silently accepted.
func TestCheckTransportTLSPosture_RejectsInvalidAllowedCiphers(t *testing.T) {
	c := cfgWith(true, true, false, false, false)
	// TLS_AES_128_GCM_SHA256 is a TLS 1.3 suite name — TLS 1.3 doesn't support
	// per-suite selection via tls.Config.CipherSuites, so it's not in the TLS 1.2
	// allowlist and must be rejected, not silently accepted.
	c.Server.HTTP.TLS.AllowedCiphers = []string{"TLS_AES_128_GCM_SHA256"}

	if err := checkTransportTLSPosture(c); err == nil {
		t.Fatal("an unrecognized/TLS-1.3-only cipher suite name must fail closed at startup")
	}
}

// protocol_versions remains a separate, still-unwired tuning field (out of scope for
// #333) — setting it must still only warn, not fail, and must not mention
// allowed_ciphers (which is no longer a dead setting).
func TestCheckTransportTLSPosture_ProtocolVersionsStillWarns(t *testing.T) {
	c := cfgWith(true, true, false, false, false)
	c.Server.HTTP.ProtocolVersions = []string{"TLS1.3"}

	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	if err := checkTransportTLSPosture(c); err != nil {
		t.Fatalf("a set protocol_versions must warn, not fail: %v", err)
	}
	if !strings.Contains(buf.String(), "protocol_versions") {
		t.Errorf("expected a warning mentioning protocol_versions, got log output: %q", buf.String())
	}
}

// A cleartext HTTP listener with no trusted_proxies configured must warn — that
// combination silently breaks per-client IP derivation (rate limiting, audit logging)
// for the documented "TLS terminated by a reverse proxy in front" topology, since
// middleware.ClientIP falls back to the raw TCP peer (the proxy's own address) when
// trusted_proxies is empty.
func TestCheckTransportTLSPosture_WarnsOnEmptyTrustedProxiesWithCleartextHTTP(t *testing.T) {
	c := cfgWith(true, false, false, false, false)

	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	if err := checkTransportTLSPosture(c); err != nil {
		t.Fatalf("cleartext HTTP without require must not fail: %v", err)
	}
	if !strings.Contains(buf.String(), "trusted_proxies") {
		t.Errorf("expected a warning mentioning trusted_proxies, got log output: %q", buf.String())
	}
}

// The same listener with trusted_proxies set must NOT emit that warning.
func TestCheckTransportTLSPosture_NoTrustedProxiesWarningWhenSet(t *testing.T) {
	c := cfgWith(true, false, false, false, false)
	c.Server.HTTP.TrustedProxies = []string{"10.0.0.0/8"}

	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	if err := checkTransportTLSPosture(c); err != nil {
		t.Fatalf("cleartext HTTP without require must not fail: %v", err)
	}
	if strings.Contains(buf.String(), "trusted_proxies") {
		t.Errorf("did not expect a trusted_proxies warning once it's configured, got log output: %q", buf.String())
	}
}

// A cleartext gRPC listener has no ClientIP middleware wired to it, so it must never
// emit the trusted_proxies warning regardless of TrustedProxies being empty.
func TestCheckTransportTLSPosture_NoTrustedProxiesWarningForGRPC(t *testing.T) {
	c := cfgWith(false, false, true, false, false)

	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	if err := checkTransportTLSPosture(c); err != nil {
		t.Fatalf("cleartext gRPC without require must not fail: %v", err)
	}
	if strings.Contains(buf.String(), "trusted_proxies") {
		t.Errorf("gRPC listener must not trigger the HTTP-only trusted_proxies warning, got log output: %q", buf.String())
	}
}

// #172: AutoCert mode must not silently discard the hardened MinVersion/CipherSuites
// — buildAutoCertTLSConfig (the AutoCert-mode config builder) must apply the same
// hardening as the non-AutoCert path (createTLSConfig).
func TestBuildAutoCertTLSConfig_AppliesHardening(t *testing.T) {
	tlsConfig, err := buildAutoCertTLSConfig([]string{"example.com"}, config.TLSConfig{})
	if err != nil {
		t.Fatalf("buildAutoCertTLSConfig: %v", err)
	}
	if tlsConfig == nil {
		t.Fatal("buildAutoCertTLSConfig must not return nil")
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want tls.VersionTLS12", tlsConfig.MinVersion)
	}
	if len(tlsConfig.CipherSuites) == 0 {
		t.Fatal("CipherSuites must not be empty on the AutoCert-derived config")
	}
	// The autocert.Manager must still be the certificate source (GetCertificate set).
	if tlsConfig.GetCertificate == nil {
		t.Error("GetCertificate must still be wired from the autocert.Manager")
	}
}

// The non-AutoCert path (createTLSConfig) must apply the identical hardening, so both
// modes converge on the same TLS posture.
func TestCreateTLSConfig_NonAutoCertAppliesHardening(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCert(t, dir)

	cfg := &config.Config{}
	cfg.Server.HTTP.TLS.Enabled = true
	cfg.Server.HTTP.TLS.CertFile = certFile
	cfg.Server.HTTP.TLS.KeyFile = keyFile

	tlsConfig, err := createTLSConfig(cfg)
	if err != nil {
		t.Fatalf("createTLSConfig: %v", err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want tls.VersionTLS12", tlsConfig.MinVersion)
	}
	if len(tlsConfig.CipherSuites) == 0 {
		t.Fatal("CipherSuites must not be empty")
	}
}

// #333 regression: when AllowedCiphers is unset, both createTLSConfig (non-AutoCert)
// and buildAutoCertTLSConfig (AutoCert) must keep the existing hardcoded secure default
// — an operator who has never touched tls.allowed_ciphers must see no change in TLS
// posture.
func TestApplyTLSHardening_DefaultPreservedWhenAllowedCiphersUnset(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCert(t, dir)

	cfg := &config.Config{}
	cfg.Server.HTTP.TLS.Enabled = true
	cfg.Server.HTTP.TLS.CertFile = certFile
	cfg.Server.HTTP.TLS.KeyFile = keyFile

	tlsConfig, err := createTLSConfig(cfg)
	if err != nil {
		t.Fatalf("createTLSConfig: %v", err)
	}
	if !cipherSuitesEqual(tlsConfig.CipherSuites, hardenedCipherSuites) {
		t.Errorf("CipherSuites = %v, want the unchanged hardcoded default %v", tlsConfig.CipherSuites, hardenedCipherSuites)
	}

	autoCertTLSConfig, err := buildAutoCertTLSConfig([]string{"example.com"}, config.TLSConfig{})
	if err != nil {
		t.Fatalf("buildAutoCertTLSConfig: %v", err)
	}
	if !cipherSuitesEqual(autoCertTLSConfig.CipherSuites, hardenedCipherSuites) {
		t.Errorf("AutoCert CipherSuites = %v, want the unchanged hardcoded default %v", autoCertTLSConfig.CipherSuites, hardenedCipherSuites)
	}
}

// #333: when AllowedCiphers is configured with a valid, specific TLS 1.2 AEAD suite
// list, the resulting tls.Config must reflect exactly that list — not the hardcoded
// default — on both the non-AutoCert and AutoCert HTTP paths.
func TestApplyTLSHardening_HonorsConfiguredAllowedCiphers(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCert(t, dir)

	configured := []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}
	want := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

	cfg := &config.Config{}
	cfg.Server.HTTP.TLS.Enabled = true
	cfg.Server.HTTP.TLS.CertFile = certFile
	cfg.Server.HTTP.TLS.KeyFile = keyFile
	cfg.Server.HTTP.TLS.AllowedCiphers = configured

	tlsConfig, err := createTLSConfig(cfg)
	if err != nil {
		t.Fatalf("createTLSConfig: %v", err)
	}
	if !cipherSuitesEqual(tlsConfig.CipherSuites, want) {
		t.Errorf("CipherSuites = %v, want the configured %v (not the hardcoded default %v)", tlsConfig.CipherSuites, want, hardenedCipherSuites)
	}

	autoCertTLSConfig, err := buildAutoCertTLSConfig([]string{"example.com"}, cfg.Server.HTTP.TLS)
	if err != nil {
		t.Fatalf("buildAutoCertTLSConfig: %v", err)
	}
	if !cipherSuitesEqual(autoCertTLSConfig.CipherSuites, want) {
		t.Errorf("AutoCert CipherSuites = %v, want the configured %v", autoCertTLSConfig.CipherSuites, want)
	}
}

// #333: an invalid/weak/deprecated cipher suite name must be rejected, not silently
// accepted, by both createTLSConfig and buildAutoCertTLSConfig.
func TestApplyTLSHardening_RejectsWeakOrUnknownCipher(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCert(t, dir)

	for _, name := range []string{
		"TLS_RSA_WITH_RC4_128_SHA",              // RC4: broken
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",         // 3DES: broken
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", // CBC-mode: deprecated
		"not-a-real-cipher-suite",               // plain typo
	} {
		cfg := &config.Config{}
		cfg.Server.HTTP.TLS.Enabled = true
		cfg.Server.HTTP.TLS.CertFile = certFile
		cfg.Server.HTTP.TLS.KeyFile = keyFile
		cfg.Server.HTTP.TLS.AllowedCiphers = []string{name}

		if _, err := createTLSConfig(cfg); err == nil {
			t.Errorf("createTLSConfig must reject weak/unknown cipher suite %q", name)
		}
		if _, err := buildAutoCertTLSConfig([]string{"example.com"}, cfg.Server.HTTP.TLS); err == nil {
			t.Errorf("buildAutoCertTLSConfig must reject weak/unknown cipher suite %q", name)
		}
	}
}

// cipherSuitesEqual reports whether two ordered cipher-suite ID slices are identical.
func cipherSuitesEqual(a, b []uint16) bool {
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
