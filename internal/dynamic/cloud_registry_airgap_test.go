//go:build noaws && noazure && nogcp

package dynamic

import "testing"

// TestAirgapProfile_OnlyKubernetesRegistered proves the ADR-109 step 6
// AIR-GAPPED profile (noaws,noazure,nogcp together) excludes every cloud-IAM
// dynamic-secret backend at once, while kubernetes — which stays in
// air-gapped per ADR-109's open-questions decision (on-prem k8s is a
// legitimate air-gapped use) — remains registered.
func TestAirgapProfile_OnlyKubernetesRegistered(t *testing.T) {
	for _, backendType := range []string{"aws-sts", "azure", "gcp"} {
		if _, err := New(backendType, false, false); err == nil {
			t.Errorf("New(%q) in the air-gapped profile: expected an error (not available)", backendType)
		}
	}
	if _, err := New("kubernetes", false, false); err != nil {
		t.Errorf("New(\"kubernetes\") in the air-gapped profile: expected no error (kubernetes stays air-gapped), got %v", err)
	}
	if got := len(cloudEngines); got != 1 {
		t.Fatalf("cloudEngines has %d entries in the air-gapped profile, want exactly 1 (kubernetes)", got)
	}
}
