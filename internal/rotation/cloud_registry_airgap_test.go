//go:build noaws && noazure && nogcp

package rotation

import "testing"

// TestAirgapProfile_NoCloudExecutorsRegistered proves the ADR-109 step 6
// AIR-GAPPED profile (noaws,noazure,nogcp together) excludes every
// generate-upstream cloud rotation backend at once.
func TestAirgapProfile_NoCloudExecutorsRegistered(t *testing.T) {
	for _, kind := range []string{"aws-iam", "azure-app", "gcp-service-account"} {
		if _, ok := LookupCloudExecutor(kind, CloudExecutorParams{Name: "x"}); ok {
			t.Errorf("LookupCloudExecutor(%q) in the air-gapped profile: expected ok=false", kind)
		}
	}
	if got := len(cloudExecutors); got != 0 {
		t.Fatalf("cloudExecutors has %d entries in the air-gapped profile, want exactly 0", got)
	}
}
