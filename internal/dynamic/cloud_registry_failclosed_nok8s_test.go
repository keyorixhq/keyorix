//go:build nok8s

package dynamic

import (
	"strings"
	"testing"
)

// TestNew_Kubernetes_NoK8sBuild_FailsClosed is the ADR-109 step 6 S2 proof for
// the nok8s tag (completeness only — no supported profile sets this tag
// today; see kubernetes.go's own doc comment) — see
// cloud_registry_failclosed_noaws_test.go's sibling for the full rationale.
func TestNew_Kubernetes_NoK8sBuild_FailsClosed(t *testing.T) {
	eng, err := New("kubernetes", false, false)
	if err == nil {
		t.Fatal("New(\"kubernetes\") in a nok8s build: expected an error, got nil")
	}
	if eng != nil {
		t.Fatalf("New(\"kubernetes\") in a nok8s build: expected a nil engine alongside the error, got %#v", eng)
	}
	if !strings.Contains(err.Error(), "kubernetes") || !strings.Contains(err.Error(), "not available in this build") {
		t.Fatalf("error must name the backend and say it is unavailable in this build, got: %v", err)
	}
	if _, ok := cloudEngines["kubernetes"]; ok {
		t.Fatal("cloudEngines must not register \"kubernetes\" in a nok8s build")
	}
}
