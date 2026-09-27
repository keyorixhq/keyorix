//go:build noazure

package dynamic

import (
	"strings"
	"testing"
)

// TestNew_Azure_NoAzureBuild_FailsClosed is the ADR-109 step 6 S2 proof for
// the noazure tag — see cloud_registry_failclosed_noaws_test.go's sibling for
// the full rationale.
func TestNew_Azure_NoAzureBuild_FailsClosed(t *testing.T) {
	eng, err := New("azure", false, false)
	if err == nil {
		t.Fatal("New(\"azure\") in a noazure build: expected an error, got nil")
	}
	if eng != nil {
		t.Fatalf("New(\"azure\") in a noazure build: expected a nil engine alongside the error, got %#v", eng)
	}
	if !strings.Contains(err.Error(), "azure") || !strings.Contains(err.Error(), "not available in this build") {
		t.Fatalf("error must name the backend and say it is unavailable in this build, got: %v", err)
	}
	if _, ok := cloudEngines["azure"]; ok {
		t.Fatal("cloudEngines must not register \"azure\" in a noazure build")
	}
}
