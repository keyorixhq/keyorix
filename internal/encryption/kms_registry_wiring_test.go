//go:build !noaws && !noazure && !nogcp

package encryption

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestFullBuildRegistersEveryCloudKMSProvider is the S1 "no behaviour change
// for the default (full) build" proof (ADR-109 step 6): it asserts every
// cloud KMS provider a pre-step-6 origin/main's buildSingleProvider resolved
// by calling its constructor directly (aws-kms, gcp-kms, azure-kms) is still
// REGISTERED in the full build, via the cloudKMSProviders registry those
// providers' own init()s populate. This only proves registration (ok=true),
// not that construction succeeds — a real awskms.New/gcpkms.New/azurekms.New
// call reaches out for live cloud credentials, unavailable in CI (see
// gcpkms_audit_sink_wiring_test.go's own note on the same constraint) — so a
// non-nil error from the registered constructor is expected and not a
// failure; only ok=false (not registered at all) is.
func TestFullBuildRegistersEveryCloudKMSProvider(t *testing.T) {
	want := []string{"aws-kms", "gcp-kms", "azure-kms"}
	for _, kmsType := range want {
		t.Run(kmsType, func(t *testing.T) {
			kp := &config.KeyProviderConfig{Type: kmsType, KMSKeyID: "wiring-test-key"}
			_, ok, _ := newCloudKMSProvider(context.Background(), kmsType, kp, t.TempDir(), nil)
			if !ok {
				t.Fatalf("newCloudKMSProvider(%q) in the full build: expected ok=true (registered)", kmsType)
			}
		})
	}
	if got := len(cloudKMSProviders); got != len(want) {
		t.Fatalf("cloudKMSProviders has %d entries, want exactly %d (%v) — a full build must register precisely these, no more, no fewer", got, len(want), want)
	}
}
