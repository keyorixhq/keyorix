//go:build !noaws && !noazure && !nogcp

package rotation

import "testing"

// TestFullBuildRegistersEveryCloudExecutor is the S1 "no behaviour change for
// the default (full) build" proof (ADR-109 step 6): it asserts
// LookupCloudExecutor resolves every generate-upstream cloud rotation backend a
// pre-step-6 origin/main's wireBackendRotation resolved by calling its
// constructor directly (aws-iam, gcp-service-account, azure-app), now via the
// cloudExecutors registry those backends' own init()s populate. A regression
// here means either a backend stopped registering itself, or the registry
// lookup broke — either way, the full build silently lost a backend it used
// to have.
func TestFullBuildRegistersEveryCloudExecutor(t *testing.T) {
	want := []string{"aws-iam", "gcp-service-account", "azure-app"}
	for _, kind := range want {
		t.Run(kind, func(t *testing.T) {
			exec, ok := LookupCloudExecutor(kind, CloudExecutorParams{Name: "wiring-test", AllowedRefs: []string{"x"}})
			if !ok {
				t.Fatalf("LookupCloudExecutor(%q) in the full build: expected ok=true", kind)
			}
			if exec == nil {
				t.Fatalf("LookupCloudExecutor(%q) in the full build: expected a non-nil executor", kind)
			}
			if exec.Type() != kind {
				t.Fatalf("LookupCloudExecutor(%q).Type() = %q, want %q", kind, exec.Type(), kind)
			}
		})
	}
	if got := len(cloudExecutors); got != len(want) {
		t.Fatalf("cloudExecutors has %d entries, want exactly %d (%v) — a full build must register precisely these, no more, no fewer", got, len(want), want)
	}
}
