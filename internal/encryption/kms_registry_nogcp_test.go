//go:build nogcp && !noaws && !noazure

package encryption

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestNoGCPBuild_GCPKMSNotRegistered is B1 (ADR-109 step 6, S2)'s per-tag
// registry proof: a nogcp build never registers "gcp-kms".
func TestNoGCPBuild_GCPKMSNotRegistered(t *testing.T) {
	kp := &config.KeyProviderConfig{Type: "gcp-kms", KMSKeyID: "wiring-test-key"}
	provider, ok, err := newCloudKMSProvider(context.Background(), "gcp-kms", kp, t.TempDir(), nil)
	if ok || provider != nil {
		t.Fatalf("newCloudKMSProvider(\"gcp-kms\") in a nogcp build: expected ok=false, nil provider; got ok=%v provider=%v err=%v", ok, provider, err)
	}
}

// TestNoGCPBuild_OtherKMSProvidersStillRegistered proves nogcp excludes ONLY
// gcp-kms.
func TestNoGCPBuild_OtherKMSProvidersStillRegistered(t *testing.T) {
	for _, kmsType := range []string{"aws-kms", "azure-kms"} {
		kp := &config.KeyProviderConfig{Type: kmsType, KMSKeyID: "wiring-test-key"}
		if _, ok, _ := newCloudKMSProvider(context.Background(), kmsType, kp, t.TempDir(), nil); !ok {
			t.Errorf("newCloudKMSProvider(%q) in a nogcp build: expected ok=true (nogcp must not exclude it)", kmsType)
		}
	}
}

// TestNoGCPBuild_BuildSingleProvider_FailsClosed confirms the ADR-109 step 6
// "not available in this build" error surfaces through buildSingleProvider.
func TestNoGCPBuild_BuildSingleProvider_FailsClosed(t *testing.T) {
	kp := &config.KeyProviderConfig{Type: "gcp-kms", KMSKeyID: "wiring-test-key"}
	provider, err := buildSingleProvider(kp, t.TempDir(), "", "", nil)
	if err == nil || provider != nil {
		t.Fatalf("buildSingleProvider(gcp-kms) in a nogcp build: expected an error and nil provider; got provider=%v err=%v", provider, err)
	}
}
