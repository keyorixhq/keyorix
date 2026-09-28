// kms_azurekms.go — registers the azure-kms key provider (ADR-109 step 6). A
// noazure build (see kms_azurekms_noazure.go) compiles this file out
// entirely, dropping internal/crypto/azurekms (and the Azure SDK packages it
// alone pulls into this package) from the binary.
//
//go:build !noazure

package encryption

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/crypto/azurekms"
)

func init() {
	registerCloudKMSProvider("azure-kms", func(ctx context.Context, kp *config.KeyProviderConfig, baseDir string, _ KMSFallbackHook) (crypto.KeyProvider, error) {
		// #123: Azure Key Vault wraps with RSA-OAEP, which has no additional-
		// authenticated-data input, so the wrapped KEK cannot be bound to an
		// install this way — full stop, there is no fallback-vs-strict
		// distinction to make (there was never a bound path). A hard refusal to
		// start is the fail-closed behavior: the operator must either drop
		// kms_encryption_context (accepting the shared-CMK exposure consciously)
		// or switch to a per-install key.
		if len(kp.KMSEncryptionContext) > 0 {
			return nil, fmt.Errorf("azure-kms: kms_encryption_context is set but unsupported (RSA-OAEP key wrap has no AAD input) — remove it, or use a per-install Key Vault key to avoid shared-key unwrap")
		}
		kmsClient, err := azurekms.New(ctx, kp.KMSKeyID)
		if err != nil {
			return nil, err
		}
		return crypto.NewKMSKeyProvider(kmsClient, "azure-kms", baseDir, kp.WrappedKeyPath), nil
	})
}
