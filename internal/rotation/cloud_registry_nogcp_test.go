//go:build nogcp && !noaws && !noazure

package rotation

import "testing"

// TestLookupCloudExecutor_GCPServiceAccount_NotRegisteredInNoGCPBuild is B1
// (ADR-109 step 6, S2)'s per-tag registry proof: a nogcp build never
// registers "gcp-service-account", so rotation.LookupCloudExecutor reports
// not-found and server/main.go's wireBackendRotation fails closed instead of
// silently returning a broken executor.
func TestLookupCloudExecutor_GCPServiceAccount_NotRegisteredInNoGCPBuild(t *testing.T) {
	_, ok := LookupCloudExecutor("gcp-service-account", CloudExecutorParams{Name: "x"})
	if ok {
		t.Fatal("gcp-service-account must not be registered in a nogcp build")
	}
}

// TestLookupCloudExecutor_NoGCPBuild_OtherExecutorsStillRegistered proves
// nogcp excludes ONLY gcp-service-account.
func TestLookupCloudExecutor_NoGCPBuild_OtherExecutorsStillRegistered(t *testing.T) {
	for _, kind := range []string{"aws-iam", "azure-app"} {
		if _, ok := LookupCloudExecutor(kind, CloudExecutorParams{Name: "x"}); !ok {
			t.Errorf("LookupCloudExecutor(%q) in a nogcp build: expected ok=true (nogcp must not exclude it)", kind)
		}
	}
}
