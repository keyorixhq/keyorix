//go:build !noazure

package encryption

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewKeyProviderFromConfig_AzureKMS_WithEncryptionContext_Error moved out
// of encryption_s24_test.go into its own //go:build !noazure file (ADR-109
// step 6): it needs the real azure-kms registration (kms_azurekms.go) to
// reach the RSA-OAEP/AAD check inside that constructor's closure — in a
// noazure build, newCloudKMSProvider reports not-registered before that
// check is ever reached, which is a different (also correct, see
// TestInitializeEncryption_AzureKMS_NoAzureBuild_FailsBoot in server/) but
// distinct failure mode this test must not be run against.
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
