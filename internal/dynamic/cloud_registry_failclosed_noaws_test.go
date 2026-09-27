//go:build noaws

package dynamic

import (
	"strings"
	"testing"
)

// TestNew_AWSSTS_NoAWSBuild_FailsClosed is the ADR-109 step 6 S2 proof for the
// noaws tag: New("aws-sts") must not silently succeed or return a broken-but-
// non-nil engine — it must report a clear, build-naming error, and the
// returned engine must be nil (no partial value a careless caller could use).
func TestNew_AWSSTS_NoAWSBuild_FailsClosed(t *testing.T) {
	eng, err := New("aws-sts", false, false)
	if err == nil {
		t.Fatal("New(\"aws-sts\") in a noaws build: expected an error, got nil")
	}
	if eng != nil {
		t.Fatalf("New(\"aws-sts\") in a noaws build: expected a nil engine alongside the error, got %#v", eng)
	}
	if !strings.Contains(err.Error(), "aws-sts") || !strings.Contains(err.Error(), "not available in this build") {
		t.Fatalf("error must name the backend and say it is unavailable in this build, got: %v", err)
	}
	if _, ok := cloudEngines["aws-sts"]; ok {
		t.Fatal("cloudEngines must not register \"aws-sts\" in a noaws build")
	}
}
