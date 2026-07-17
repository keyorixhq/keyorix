// encryption_s17_test.go — coverage uplift for NewKeyProviderFromConfig
// (target: service.go:92, currently 47.8%).
//
// The KMS provider branches (aws-kms, gcp-kms, azure-kms) reach external
// cloud credentials on New(), so we exercise those branches via error paths
// that fire before any network call (empty kms_key_id → the SDK's own guard)
// or via the azure-kms encryption-context rejection that fires inside
// NewKeyProviderFromConfig itself.
package encryption

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestNewKeyProviderFromConfig_UnknownType_ErrorMessage verifies the default
// branch error message includes the full supported-list string.
func TestNewKeyProviderFromConfig_UnknownType_ErrorMessage(t *testing.T) {
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{Type: "bogus-provider"},
	}
	_, err := NewKeyProviderFromConfig(cfg, t.TempDir(), "")
	if err == nil {
		t.Fatal("expected error for unknown provider type, got nil")
	}
	if !strings.Contains(err.Error(), "unknown encryption key_provider type") {
		t.Errorf("expected 'unknown encryption key_provider type' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "bogus-provider") {
		t.Errorf("expected the unknown type name in error, got: %v", err)
	}
}

// TestNewKeyProviderFromConfig_AWSKMS_EmptyKeyID tests the aws-kms case when
// kms_key_id is empty. awskms.New returns an error immediately (before any
// network call), so NewKeyProviderFromConfig must propagate it.
func TestNewKeyProviderFromConfig_AWSKMS_EmptyKeyID(t *testing.T) {
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:     "aws-kms",
			KMSKeyID: "", // triggers awskms.New's own guard
		},
	}
	_, err := NewKeyProviderFromConfig(cfg, t.TempDir(), "")
	if err == nil {
		t.Fatal("expected error for aws-kms with empty kms_key_id, got nil")
	}
}

// TestNewKeyProviderFromConfig_GCPKMS_EmptyKeyID tests the gcp-kms case when
// kms_key_id is empty. gcpkms.New returns an error immediately.
func TestNewKeyProviderFromConfig_GCPKMS_EmptyKeyID(t *testing.T) {
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:     "gcp-kms",
			KMSKeyID: "",
		},
	}
	_, err := NewKeyProviderFromConfig(cfg, t.TempDir(), "")
	if err == nil {
		t.Fatal("expected error for gcp-kms with empty kms_key_id, got nil")
	}
}

// TestNewKeyProviderFromConfig_AzureKMS_EmptyKeyID tests the azure-kms case
// when kms_key_id is empty. azurekms.New returns an error immediately.
func TestNewKeyProviderFromConfig_AzureKMS_EmptyKeyID(t *testing.T) {
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:     "azure-kms",
			KMSKeyID: "",
		},
	}
	_, err := NewKeyProviderFromConfig(cfg, t.TempDir(), "")
	if err == nil {
		t.Fatal("expected error for azure-kms with empty kms_key_id, got nil")
	}
}

// TestNewKeyProviderFromConfig_AzureKMS_InvalidKeyURL tests the azure-kms
// case when kms_key_id is set but not a valid Key Vault URL. parseKeyID
// returns an error, which azurekms.New propagates.
func TestNewKeyProviderFromConfig_AzureKMS_InvalidKeyURL(t *testing.T) {
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:     "azure-kms",
			KMSKeyID: "not-a-url",
		},
	}
	_, err := NewKeyProviderFromConfig(cfg, t.TempDir(), "")
	if err == nil {
		t.Fatal("expected error for azure-kms with invalid key URL, got nil")
	}
}

// TestNewKeyProviderFromConfig_AzureKMS_WithEncryptionContext_IsRejected
// verifies the fail-closed guard added in #123: azure-kms must reject any
// kms_encryption_context because RSA-OAEP key wrap has no AAD input. This
// branch fires inside NewKeyProviderFromConfig itself (before azurekms.New).
func TestNewKeyProviderFromConfig_AzureKMS_WithEncryptionContext_IsRejected(t *testing.T) {
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:                 "azure-kms",
			KMSKeyID:             "https://vault.vault.azure.net/keys/kek/v1",
			KMSEncryptionContext: map[string]string{"install": "prod"},
		},
	}
	_, err := NewKeyProviderFromConfig(cfg, t.TempDir(), "")
	if err == nil {
		t.Fatal("expected error for azure-kms with encryption context, got nil")
	}
	if !strings.Contains(err.Error(), "azure-kms") {
		t.Errorf("expected 'azure-kms' in error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "kms_encryption_context") {
		t.Errorf("expected 'kms_encryption_context' in error, got: %v", err)
	}
}
