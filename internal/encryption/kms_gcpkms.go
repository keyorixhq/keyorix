// kms_gcpkms.go — registers the gcp-kms key provider (ADR-109 step 6). A
// nogcp build (see kms_gcpkms_nogcp.go) compiles this file out entirely,
// dropping internal/crypto/gcpkms (and the GCP SDK packages it alone pulls
// into this package) from the binary.
//
//go:build !nogcp

package encryption

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/crypto/gcpkms"
)

func init() {
	registerCloudKMSProvider("gcp-kms", func(ctx context.Context, kp *config.KeyProviderConfig, baseDir string, _ KMSFallbackHook) (crypto.KeyProvider, error) {
		kmsClient, err := gcpkms.New(ctx, kp.KMSKeyID, kp.KMSEncryptionContext, kp.KMSAllowContextFallback)
		if err != nil {
			return nil, err
		}
		return crypto.NewKMSKeyProvider(kmsClient, "gcp-kms", baseDir, kp.WrappedKeyPath), nil
	})
	wireGCPKMSAuditSinkFn = func(kp *crypto.KMSKeyProvider, sink AuditSink) bool {
		sinkable, ok := kp.Client().(interface{ SetAuditSink(gcpkms.AuditSink) })
		if !ok {
			return false
		}
		sinkable.SetAuditSink(gcpkms.AuditSink(sink))
		return true
	}
}
