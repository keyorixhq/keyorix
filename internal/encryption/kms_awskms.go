// kms_awskms.go — registers the aws-kms key provider (ADR-109 step 6). A
// noaws build (see kms_awskms_noaws.go) compiles this file out entirely,
// dropping internal/crypto/awskms (and the AWS SDK packages it alone pulls
// into this package) from the binary.
//
//go:build !noaws

package encryption

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/crypto/awskms"
)

func init() {
	registerCloudKMSProvider("aws-kms", func(ctx context.Context, kp *config.KeyProviderConfig, baseDir string, hook KMSFallbackHook) (crypto.KeyProvider, error) {
		kmsClient, err := awskms.New(ctx, kp.KMSKeyID, kp.KMSEncryptionContext, kp.KMSAllowContextFallback, awskms.FallbackHook(hook))
		if err != nil {
			return nil, err
		}
		return crypto.NewKMSKeyProvider(kmsClient, "aws-kms", baseDir, kp.WrappedKeyPath), nil
	})
}
