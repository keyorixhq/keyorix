//go:build noazure

package main

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// See adr109_failclosed_noaws_test.go's header comment for the full
// rationale — this is the same set of ADR-109 step 6 S2 proofs for the
// noazure tag.

// TestWireBackendRotation_AzureApp_NoAzureBuild_FailsBoot proves a
// configured azure-app rotation backend refuses to boot in a noazure build.
func TestWireBackendRotation_AzureApp_NoAzureBuild_FailsBoot(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.AutoRotation.Backends = []config.RotationBackendConfig{
		{Name: "prod-azure-app", Type: "azure-app", AllowedRefs: []string{"svc-"}},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot with an azure-app rotation backend in a noazure build")
	}
	if !strings.Contains(err.Error(), "prod-azure-app") || !strings.Contains(err.Error(), "azure-app") {
		t.Fatalf("expected error to name the offending backend and its type, got: %v", err)
	}
	if !strings.Contains(err.Error(), "noazure") {
		t.Fatalf("expected error to name the excluding build tag, got: %v", err)
	}
}

// TestWireConnect_AzureKeyVault_NoAzureBuild_FailsBoot proves a configured
// azure-key-vault connector refuses to boot in a noazure build.
func TestWireConnect_AzureKeyVault_NoAzureBuild_FailsBoot(t *testing.T) {
	initI18n(t)
	cfg := newMinimalCfg(t)
	cfg.Connect = config.ConnectConfig{
		Enabled: true,
		Connectors: []config.ConnectorConfig{
			{Name: "prod-azure-kv", Type: "azure-key-vault", Scope: "platform", Address: "https://example.vault.azure.net"},
		},
	}
	_, _, err := initializeCoreService(cfg)
	if err == nil {
		t.Fatal("expected initializeCoreService to refuse to boot with an azure-key-vault connector in a noazure build")
	}
	if !strings.Contains(err.Error(), "prod-azure-kv") || !strings.Contains(err.Error(), "azure-key-vault") {
		t.Fatalf("expected error to name the offending connector and its type, got: %v", err)
	}
	if !strings.Contains(err.Error(), "noazure") {
		t.Fatalf("expected error to name the excluding build tag, got: %v", err)
	}
}

// TestInitializeEncryption_AzureKMS_NoAzureBuild_FailsBoot proves a
// configured azure-kms key provider refuses to boot in a noazure build, and
// that no *encryption.Service leaks out alongside the error.
func TestInitializeEncryption_AzureKMS_NoAzureBuild_FailsBoot(t *testing.T) {
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
					Type:     "azure-kms",
					KMSKeyID: "https://example.vault.azure.net/keys/unused",
				},
			},
		},
	}
	svc, err := initializeEncryption(cfg, nil)
	if err == nil {
		t.Fatal("expected initializeEncryption to fail with an azure-kms key provider in a noazure build")
	}
	if svc != nil {
		t.Fatalf("expected a nil *encryption.Service alongside the error, got %#v", svc)
	}
	if !strings.Contains(err.Error(), "azure-kms") {
		t.Fatalf("expected error to name the offending key provider type, got: %v", err)
	}
	if !strings.Contains(err.Error(), "not available in this build") {
		t.Fatalf("expected error to say the provider is unavailable in this build, got: %v", err)
	}
}
