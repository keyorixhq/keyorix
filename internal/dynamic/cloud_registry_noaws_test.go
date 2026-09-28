//go:build noaws && !noazure && !nogcp && !nok8s

package dynamic

import (
	"strings"
	"testing"
)

// TestNoAWSBuild_AWSSTSNotAvailable is B1 (ADR-109 step 6, S2)'s per-tag
// proof: a noaws build never registers "aws-sts", so New() returns the clear
// "not available in this build" error instead of silently constructing an
// engine whose underlying AWS SDK was never linked in.
func TestNoAWSBuild_AWSSTSNotAvailable(t *testing.T) {
	eng, err := New("aws-sts", false, false)
	if err == nil || eng != nil {
		t.Fatalf("New(\"aws-sts\") in a noaws build: expected a non-nil error and nil engine; got eng=%v err=%v", eng, err)
	}
	if !strings.Contains(err.Error(), "not available in this build") {
		t.Errorf("expected error to say \"not available in this build\", got: %v", err)
	}
	if !strings.Contains(err.Error(), "aws-sts") {
		t.Errorf("expected error to name the backend \"aws-sts\", got: %v", err)
	}
}

// TestNoAWSBuild_OtherCloudEnginesStillRegistered proves noaws excludes ONLY
// aws-sts among the cloud-IAM backends.
func TestNoAWSBuild_OtherCloudEnginesStillRegistered(t *testing.T) {
	for _, backendType := range []string{"gcp", "azure", "kubernetes"} {
		if _, err := New(backendType, false, false); err != nil {
			t.Errorf("New(%q) in a noaws build: expected no error (noaws must not exclude it), got %v", backendType, err)
		}
	}
}
