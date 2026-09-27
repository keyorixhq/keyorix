//go:build !noaws && !noazure && !nogcp && !nok8s

package dynamic

import "testing"

// TestFullBuildRegistersEveryCloudEngine is the S1 "no behaviour change for
// the default (full) build" proof (ADR-109 step 6): it asserts New() still
// resolves every cloud-IAM dynamic-secret backend a pre-step-6 origin/main
// resolved directly (aws-sts, gcp, azure, kubernetes — see engine.go's
// pre-change switch statement, each returning its own concrete Engine type
// with no error), now via the cloudEngines registry these backends'
// individual init()s populate. A regression here means either a backend
// stopped registering itself, or New()'s cloudEngines fallthrough broke —
// either way, the full build silently lost a backend it used to have.
func TestFullBuildRegistersEveryCloudEngine(t *testing.T) {
	want := []string{"aws-sts", "gcp", "azure", "kubernetes"}
	for _, backendType := range want {
		t.Run(backendType, func(t *testing.T) {
			eng, err := New(backendType, false, false)
			if err != nil {
				t.Fatalf("New(%q) in the full build: expected no error, got %v", backendType, err)
			}
			if eng == nil {
				t.Fatalf("New(%q) in the full build: expected a non-nil engine", backendType)
			}
		})
	}
	if got := len(cloudEngines); got != len(want) {
		t.Fatalf("cloudEngines has %d entries, want exactly %d (%v) — a full build must register precisely these, no more, no fewer", got, len(want), want)
	}
}
