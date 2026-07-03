package encryption

import (
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// #123: azure-kms has no additional-authenticated-data input for RSA-OAEP key wrap,
// so a configured kms_encryption_context can never actually bind the wrapped KEK to
// this install. This used to be a log.Printf warning only — easy to miss — and
// startup proceeded with a silently-unbound key. It must now be a hard startup
// error: the check runs BEFORE azurekms.New is reached, so this is a hermetic test
// (no Azure credentials/network needed) — a real credential/vault-URL error would
// only ever be reached if this check were bypassed.
func TestNewKeyProviderFromConfig_AzureKMSRejectsEncryptionContext(t *testing.T) {
	cfg := &config.EncryptionConfig{
		Enabled: true,
		KeyProvider: config.KeyProviderConfig{
			Type:                 "azure-kms",
			KMSKeyID:             "https://vault.vault.azure.net/keys/k",
			WrappedKeyPath:       "keys/kek.kms",
			KMSEncryptionContext: map[string]string{"keyorix-install": "inst-1"},
		},
	}
	_, err := NewKeyProviderFromConfig(cfg, t.TempDir(), "")
	if err == nil {
		t.Fatal("azure-kms with kms_encryption_context set must fail to construct, not silently ignore it")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected an 'unsupported' error explaining why, got: %v", err)
	}
}
