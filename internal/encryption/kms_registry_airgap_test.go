//go:build noaws && noazure && nogcp

package encryption

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestAirgapProfile_NoCloudKMSProvidersRegistered proves the ADR-109 step 6
// AIR-GAPPED profile (noaws,noazure,nogcp together) excludes every cloud KMS
// provider at once.
func TestAirgapProfile_NoCloudKMSProvidersRegistered(t *testing.T) {
	for _, kmsType := range []string{"aws-kms", "azure-kms", "gcp-kms"} {
		kp := &config.KeyProviderConfig{Type: kmsType, KMSKeyID: "wiring-test-key"}
		if _, ok, _ := newCloudKMSProvider(context.Background(), kmsType, kp, t.TempDir(), nil); ok {
			t.Errorf("newCloudKMSProvider(%q) in the air-gapped profile: expected ok=false", kmsType)
		}
	}
	if got := len(cloudKMSProviders); got != 0 {
		t.Fatalf("cloudKMSProviders has %d entries in the air-gapped profile, want exactly 0", got)
	}
}
