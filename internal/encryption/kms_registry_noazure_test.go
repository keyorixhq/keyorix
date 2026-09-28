//go:build noazure && !noaws && !nogcp

package encryption

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestNoAzureBuild_AzureKMSNotRegistered is B1 (ADR-109 step 6, S2)'s per-tag
// registry proof: a noazure build never registers "azure-kms".
func TestNoAzureBuild_AzureKMSNotRegistered(t *testing.T) {
	kp := &config.KeyProviderConfig{Type: "azure-kms", KMSKeyID: "wiring-test-key"}
	provider, ok, err := newCloudKMSProvider(context.Background(), "azure-kms", kp, t.TempDir(), nil)
	if ok || provider != nil {
		t.Fatalf("newCloudKMSProvider(\"azure-kms\") in a noazure build: expected ok=false, nil provider; got ok=%v provider=%v err=%v", ok, provider, err)
	}
}

// TestNoAzureBuild_OtherKMSProvidersStillRegistered proves noazure excludes
// ONLY azure-kms.
func TestNoAzureBuild_OtherKMSProvidersStillRegistered(t *testing.T) {
	for _, kmsType := range []string{"aws-kms", "gcp-kms"} {
		kp := &config.KeyProviderConfig{Type: kmsType, KMSKeyID: "wiring-test-key"}
		if _, ok, _ := newCloudKMSProvider(context.Background(), kmsType, kp, t.TempDir(), nil); !ok {
			t.Errorf("newCloudKMSProvider(%q) in a noazure build: expected ok=true (noazure must not exclude it)", kmsType)
		}
	}
}

// TestNoAzureBuild_BuildSingleProvider_FailsClosed confirms the ADR-109 step
// 6 "not available in this build" error surfaces through buildSingleProvider.
func TestNoAzureBuild_BuildSingleProvider_FailsClosed(t *testing.T) {
	kp := &config.KeyProviderConfig{Type: "azure-kms", KMSKeyID: "wiring-test-key"}
	provider, err := buildSingleProvider(kp, t.TempDir(), "", "", nil)
	if err == nil || provider != nil {
		t.Fatalf("buildSingleProvider(azure-kms) in a noazure build: expected an error and nil provider; got provider=%v err=%v", provider, err)
	}
}
