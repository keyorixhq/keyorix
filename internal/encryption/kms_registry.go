// kms_registry.go — the registration seam for cloud-KMS-backed key providers
// (ADR-109 step 6): aws-kms, gcp-kms and azure-kms each register themselves
// from an init() in their own file (kms_awskms.go/kms_gcpkms.go/kms_azurekms.go),
// guarded by that integration's //go:build !no<x> tag, with a no<x> sibling
// that registers nothing, so a no<x> build's binary never links the
// corresponding cloud SDK. buildSingleProvider (service.go) dispatches into
// this registry instead of importing internal/crypto/{awskms,azurekms,gcpkms}
// directly.
package encryption

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
)

// KMSFallbackHook mirrors awskms.FallbackHook's exact signature (a func value
// of this shape converts implicitly either way) without this always-compiled
// file importing internal/crypto/awskms — only kms_awskms.go (gated !noaws)
// does that.
type KMSFallbackHook func(ctx context.Context, keyID string)

type cloudKMSCtor func(ctx context.Context, kp *config.KeyProviderConfig, baseDir string, hook KMSFallbackHook) (crypto.KeyProvider, error)

// cloudKMSProviders holds the KMS providers registered by the current build.
var cloudKMSProviders = map[string]cloudKMSCtor{}

// registerCloudKMSProvider panics on a duplicate type — every registration
// happens from this package's own init()s, and a collision there is a
// build-time programming error, not a runtime condition to handle gracefully.
func registerCloudKMSProvider(kmsType string, ctor cloudKMSCtor) {
	if _, exists := cloudKMSProviders[kmsType]; exists {
		panic(fmt.Sprintf("encryption: duplicate KMS provider registration for %q", kmsType))
	}
	cloudKMSProviders[kmsType] = ctor
}

// newCloudKMSProvider builds the key provider for kmsType ("aws-kms", "gcp-kms"
// or "azure-kms"), if the current build registers it. ok is false when the
// build excludes it (e.g. -tags nogcp excludes "gcp-kms") — buildSingleProvider
// turns that into a clear "not available in this build" error naming the type
// and build tag, never a silent fallback.
func newCloudKMSProvider(ctx context.Context, kmsType string, kp *config.KeyProviderConfig, baseDir string, hook KMSFallbackHook) (provider crypto.KeyProvider, ok bool, err error) {
	ctor, ok := cloudKMSProviders[kmsType]
	if !ok {
		return nil, false, nil
	}
	provider, err = ctor(ctx, kp, baseDir, hook)
	return provider, true, err
}

// wireGCPKMSAuditSinkFn, when non-nil (only under a !nogcp build — see
// kms_gcpkms.go's init()), connects a gcp-kms-backed KeyProvider's client to
// this Service's audit sink. A nogcp build leaves this nil, making
// Service.wireKMSAuditSink's call a no-op — there is no gcp-kms client to wire
// in that build in the first place.
var wireGCPKMSAuditSinkFn func(kp *crypto.KMSKeyProvider, sink AuditSink) bool
