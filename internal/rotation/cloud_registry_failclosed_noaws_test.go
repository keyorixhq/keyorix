//go:build noaws

package rotation

import "testing"

// TestLookupCloudExecutor_AWSIAM_NoAWSBuild_FailsClosed is the ADR-109 step 6
// S2 proof for the noaws tag: LookupCloudExecutor("aws-iam") must report
// ok=false rather than silently returning a broken-but-usable executor, and
// aws-iam must not be present in cloudExecutors at all. server/main.go's
// wireBackendRotation turns this ok=false into a boot-time error naming both
// the backend and the build-tag exclusion mechanism — proven end-to-end by
// server's own TestWireBackendRotation_UnbuiltCloudBackend_FailsClosed, which
// depends on this exact ok=false contract.
func TestLookupCloudExecutor_AWSIAM_NoAWSBuild_FailsClosed(t *testing.T) {
	exec, ok := LookupCloudExecutor("aws-iam", CloudExecutorParams{Name: "x", Region: "us-east-1", AllowedRefs: []string{"svc-"}})
	if ok {
		t.Fatal("LookupCloudExecutor(\"aws-iam\") in a noaws build: expected ok=false")
	}
	if exec != nil {
		t.Fatalf("LookupCloudExecutor(\"aws-iam\") in a noaws build: expected a nil executor, got %#v", exec)
	}
	if _, registered := cloudExecutors["aws-iam"]; registered {
		t.Fatal("cloudExecutors must not register \"aws-iam\" in a noaws build")
	}
}
