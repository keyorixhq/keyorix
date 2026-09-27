//go:build nogcp

package dynamic

import (
	"strings"
	"testing"
)

// TestNew_GCP_NoGCPBuild_FailsClosed is the ADR-109 step 6 S2 proof for the
// nogcp tag — see cloud_registry_failclosed_noaws_test.go's sibling for the
// full rationale.
func TestNew_GCP_NoGCPBuild_FailsClosed(t *testing.T) {
	eng, err := New("gcp", false, false)
	if err == nil {
		t.Fatal("New(\"gcp\") in a nogcp build: expected an error, got nil")
	}
	if eng != nil {
		t.Fatalf("New(\"gcp\") in a nogcp build: expected a nil engine alongside the error, got %#v", eng)
	}
	if !strings.Contains(err.Error(), "gcp") || !strings.Contains(err.Error(), "not available in this build") {
		t.Fatalf("error must name the backend and say it is unavailable in this build, got: %v", err)
	}
	if _, ok := cloudEngines["gcp"]; ok {
		t.Fatal("cloudEngines must not register \"gcp\" in a nogcp build")
	}
}
