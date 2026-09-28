//go:build noaws && !noazure && !nogcp

package encryption

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestNoAWSBuild_AWSKMSNotRegistered is B1 (ADR-109 step 6, S2)'s per-tag
// registry proof: a noaws build never registers "aws-kms", so
// newCloudKMSProvider reports not-found and buildSingleProvider's
// "not available in this build" error fires instead of the AWS SDK ever
// being linked in.
func TestNoAWSBuild_AWSKMSNotRegistered(t *testing.T) {
	kp := &config.KeyProviderConfig{Type: "aws-kms", KMSKeyID: "wiring-test-key"}
	provider, ok, err := newCloudKMSProvider(context.Background(), "aws-kms", kp, t.TempDir(), nil)
	if ok || provider != nil {
		t.Fatalf("newCloudKMSProvider(\"aws-kms\") in a noaws build: expected ok=false, nil provider; got ok=%v provider=%v err=%v", ok, provider, err)
	}
}

// TestNoAWSBuild_OtherKMSProvidersStillRegistered proves noaws excludes ONLY
// aws-kms.
func TestNoAWSBuild_OtherKMSProvidersStillRegistered(t *testing.T) {
	for _, kmsType := range []string{"gcp-kms", "azure-kms"} {
		kp := &config.KeyProviderConfig{Type: kmsType, KMSKeyID: "wiring-test-key"}
		if _, ok, _ := newCloudKMSProvider(context.Background(), kmsType, kp, t.TempDir(), nil); !ok {
			t.Errorf("newCloudKMSProvider(%q) in a noaws build: expected ok=true (noaws must not exclude it)", kmsType)
		}
	}
}

// TestNoAWSBuild_BuildSingleProvider_FailsClosed confirms the ADR-109 step 6
// "not available in this build" error actually surfaces through
// buildSingleProvider (the call site every real Initialize() goes through),
// not just at the registry layer directly.
func TestNoAWSBuild_BuildSingleProvider_FailsClosed(t *testing.T) {
	kp := &config.KeyProviderConfig{Type: "aws-kms", KMSKeyID: "wiring-test-key"}
	provider, err := buildSingleProvider(kp, t.TempDir(), "", "", nil)
	if err == nil || provider != nil {
		t.Fatalf("buildSingleProvider(aws-kms) in a noaws build: expected an error and nil provider; got provider=%v err=%v", provider, err)
	}
}
