//go:build noaws && !noazure && !nogcp

package rotation

import "testing"

// TestLookupCloudExecutor_AWSIAM_NotRegisteredInNoAWSBuild is B1 (ADR-109 step
// 6, S2)'s per-tag registry proof: a noaws build never registers "aws-iam"
// (awsiam.go itself is tagged `!lean && !noaws` — under noaws alone there is
// no AWSIAMExecutor type at all), so rotation.LookupCloudExecutor reports
// not-found and server/main.go's wireBackendRotation fails closed instead of
// silently returning a broken executor.
func TestLookupCloudExecutor_AWSIAM_NotRegisteredInNoAWSBuild(t *testing.T) {
	_, ok := LookupCloudExecutor("aws-iam", CloudExecutorParams{Name: "x"})
	if ok {
		t.Fatal("aws-iam must not be registered in a noaws build")
	}
}

// TestLookupCloudExecutor_NoAWSBuild_OtherExecutorsStillRegistered proves
// noaws excludes ONLY aws-iam.
func TestLookupCloudExecutor_NoAWSBuild_OtherExecutorsStillRegistered(t *testing.T) {
	for _, kind := range []string{"gcp-service-account", "azure-app"} {
		if _, ok := LookupCloudExecutor(kind, CloudExecutorParams{Name: "x"}); !ok {
			t.Errorf("LookupCloudExecutor(%q) in a noaws build: expected ok=true (noaws must not exclude it)", kind)
		}
	}
}
