//go:build !noazure

package encryption

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestNewKeyProviderFromConfig_AzureKMS_WithEncryptionContext_Error asserts an
// azure-kms-specific validation error (kms_encryption_context is unsupported
// for this provider) — only reachable when the real azure-kms constructor is
// compiled in (see kms_azurekms.go). Moved out of encryption_s24_test.go
// (ADR-109 step 6, B1/S2), which must stay build-tag-agnostic: under a
// noazure build, buildSingleProvider never reaches this validation at all —
// it fails closed earlier with the generic "not available in this build"
// error instead (kms_registry_noazure_test.go).
func TestNewKeyProviderFromConfig_AzureKMS_WithEncryptionContext_Error(t *testing.T) {
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:                 "azure-kms",
			KMSKeyID:             "https://vault.example.com/keys/mykey",
			KMSEncryptionContext: map[string]string{"env": "prod"},
		},
	}
	_, err := NewKeyProviderFromConfig(cfg, t.TempDir(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure-kms")
	assert.Contains(t, err.Error(), "kms_encryption_context")
}
