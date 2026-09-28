//go:build nogcp && !noaws && !noazure && !nok8s

package dynamic

import (
	"strings"
	"testing"
)

// TestNoGCPBuild_GCPNotAvailable is B1 (ADR-109 step 6, S2)'s per-tag proof: a
// nogcp build never registers "gcp", so New() returns the clear "not
// available in this build" error instead of silently constructing an engine
// whose underlying GCP SDK was never linked in.
func TestNoGCPBuild_GCPNotAvailable(t *testing.T) {
	eng, err := New("gcp", false, false)
	if err == nil || eng != nil {
		t.Fatalf("New(\"gcp\") in a nogcp build: expected a non-nil error and nil engine; got eng=%v err=%v", eng, err)
	}
	if !strings.Contains(err.Error(), "not available in this build") {
		t.Errorf("expected error to say \"not available in this build\", got: %v", err)
	}
	if !strings.Contains(err.Error(), "gcp") {
		t.Errorf("expected error to name the backend \"gcp\", got: %v", err)
	}
}

// TestNoGCPBuild_OtherCloudEnginesStillRegistered proves nogcp excludes ONLY
// gcp among the cloud-IAM backends.
func TestNoGCPBuild_OtherCloudEnginesStillRegistered(t *testing.T) {
	for _, backendType := range []string{"aws-sts", "azure", "kubernetes"} {
		if _, err := New(backendType, false, false); err != nil {
			t.Errorf("New(%q) in a nogcp build: expected no error (nogcp must not exclude it), got %v", backendType, err)
		}
	}
}
