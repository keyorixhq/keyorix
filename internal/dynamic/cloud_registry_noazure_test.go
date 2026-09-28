//go:build noazure && !noaws && !nogcp && !nok8s

package dynamic

import (
	"strings"
	"testing"
)

// TestNoAzureBuild_AzureNotAvailable is B1 (ADR-109 step 6, S2)'s per-tag
// proof: a noazure build never registers "azure", so New() returns the clear
// "not available in this build" error instead of silently constructing an
// engine whose underlying Azure SDK was never linked in.
func TestNoAzureBuild_AzureNotAvailable(t *testing.T) {
	eng, err := New("azure", false, false)
	if err == nil || eng != nil {
		t.Fatalf("New(\"azure\") in a noazure build: expected a non-nil error and nil engine; got eng=%v err=%v", eng, err)
	}
	if !strings.Contains(err.Error(), "not available in this build") {
		t.Errorf("expected error to say \"not available in this build\", got: %v", err)
	}
	if !strings.Contains(err.Error(), "azure") {
		t.Errorf("expected error to name the backend \"azure\", got: %v", err)
	}
}

// TestNoAzureBuild_OtherCloudEnginesStillRegistered proves noazure excludes
// ONLY azure among the cloud-IAM backends.
func TestNoAzureBuild_OtherCloudEnginesStillRegistered(t *testing.T) {
	for _, backendType := range []string{"aws-sts", "gcp", "kubernetes"} {
		if _, err := New(backendType, false, false); err != nil {
			t.Errorf("New(%q) in a noazure build: expected no error (noazure must not exclude it), got %v", backendType, err)
		}
	}
}
