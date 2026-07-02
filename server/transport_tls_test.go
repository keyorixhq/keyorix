package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
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

// #172: AutoCert mode must not silently discard the hardened MinVersion/CipherSuites
// — buildAutoCertTLSConfig (the AutoCert-mode config builder) must apply the same
// hardening as the non-AutoCert path (createTLSConfig).
func TestBuildAutoCertTLSConfig_AppliesHardening(t *testing.T) {
	tlsConfig := buildAutoCertTLSConfig([]string{"example.com"})
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
