//go:build nogcp

package rotation

import "testing"

// TestLookupCloudExecutor_GCPServiceAccount_NoGCPBuild_FailsClosed is the
// ADR-109 step 6 S2 proof for the nogcp tag — see
// cloud_registry_failclosed_noaws_test.go's sibling for the full rationale.
func TestLookupCloudExecutor_GCPServiceAccount_NoGCPBuild_FailsClosed(t *testing.T) {
	exec, ok := LookupCloudExecutor("gcp-service-account", CloudExecutorParams{Name: "x", AllowedRefs: []string{"svc-"}})
	if ok {
		t.Fatal("LookupCloudExecutor(\"gcp-service-account\") in a nogcp build: expected ok=false")
	}
	if exec != nil {
		t.Fatalf("LookupCloudExecutor(\"gcp-service-account\") in a nogcp build: expected a nil executor, got %#v", exec)
	}
	if _, registered := cloudExecutors["gcp-service-account"]; registered {
		t.Fatal("cloudExecutors must not register \"gcp-service-account\" in a nogcp build")
	}
}
