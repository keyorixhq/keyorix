//go:build nogcp

package main

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// See adr109_failclosed_noaws_test.go's header comment for the full
// rationale — this is the same set of ADR-109 step 6 S2 proofs for the
// nogcp tag.

// TestWireBackendRotation_GCPServiceAccount_NoGCPBuild_FailsBoot proves a
// configured gcp-service-account rotation backend refuses to boot in a
// nogcp build.
func TestWireBackendRotation_GCPServiceAccount_NoGCPBuild_FailsBoot(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.AutoRotation.Backends = []config.RotationBackendConfig{
		{Name: "prod-gcp-sa", Type: "gcp-service-account", AllowedRefs: []string{"svc-"}},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot with a gcp-service-account rotation backend in a nogcp build")
	}
	if !strings.Contains(err.Error(), "prod-gcp-sa") || !strings.Contains(err.Error(), "gcp-service-account") {
		t.Fatalf("expected error to name the offending backend and its type, got: %v", err)
	}
	if !strings.Contains(err.Error(), "nogcp") {
		t.Fatalf("expected error to name the excluding build tag, got: %v", err)
	}
}

// TestWireConnect_GCPSecretManager_NoGCPBuild_FailsBoot proves a configured
// gcp-secret-manager connector refuses to boot in a nogcp build.
func TestWireConnect_GCPSecretManager_NoGCPBuild_FailsBoot(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "prod-gcp-sm", Type: "gcp-secret-manager", Scope: "platform", ProjectID: "example-project"},
		},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot with a gcp-secret-manager connector in a nogcp build")
	}
	if !strings.Contains(err.Error(), "prod-gcp-sm") || !strings.Contains(err.Error(), "gcp-secret-manager") {
		t.Fatalf("expected error to name the offending connector and its type, got: %v", err)
	}
	if !strings.Contains(err.Error(), "nogcp") {
		t.Fatalf("expected error to name the excluding build tag, got: %v", err)
	}
}

// TestInitializeEncryption_GCPKMS_NoGCPBuild_FailsBoot proves a configured
// gcp-kms key provider refuses to boot in a nogcp build, and that no
// *encryption.Service leaks out alongside the error.
func TestInitializeEncryption_GCPKMS_NoGCPBuild_FailsBoot(t *testing.T) {
	t.Setenv("KEYORIX_MASTER_PASSWORD", "unused-not-reached")
	t.Chdir(t.TempDir())
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:     "local",
			Database: config.DatabaseConfig{Path: "test.db"},
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  "dek.json",
				SaltPath: "salt.bin",
				KeyProvider: config.KeyProviderConfig{
					Type:     "gcp-kms",
					KMSKeyID: "projects/p/locations/l/keyRings/r/cryptoKeys/unused",
				},
			},
		},
	}
	svc, err := initializeEncryption(cfg, nil)
	if err == nil {
		t.Fatal("expected initializeEncryption to fail with a gcp-kms key provider in a nogcp build")
	}
	if svc != nil {
		t.Fatalf("expected a nil *encryption.Service alongside the error, got %#v", svc)
	}
	if !strings.Contains(err.Error(), "gcp-kms") {
		t.Fatalf("expected error to name the offending key provider type, got: %v", err)
	}
	if !strings.Contains(err.Error(), "not available in this build") {
		t.Fatalf("expected error to say the provider is unavailable in this build, got: %v", err)
	}
}
