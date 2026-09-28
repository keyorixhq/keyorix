package main

import "testing"

// requireCloudBuild skips a test whose config names a cloud integration this
// test binary was compiled without (-tags noaws/noazure/nogcp, the ADR-109
// air-gapped profile). Such a config is SUPPOSED to refuse to boot there;
// that refusal is asserted by the dedicated *_failclosed_no<x>_test.go files,
// so these full-build wiring tests only make sense when the SDK is linked.
func requireCloudBuild(t *testing.T, aws, azure, gcp bool) {
	t.Helper()
	if (aws && !buildHasAWS) || (azure && !buildHasAzure) || (gcp && !buildHasGCP) {
		t.Skip("cloud integration excluded by build tag (air-gapped profile); fail-closed behavior is covered by *_failclosed_no<x>_test.go")
	}
}
