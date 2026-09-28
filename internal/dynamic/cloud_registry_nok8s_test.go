//go:build nok8s && !noaws && !noazure && !nogcp

package dynamic

import (
	"strings"
	"testing"
)

// TestNoK8sBuild_KubernetesNotAvailable is B1 (ADR-109 step 6, S2)'s per-tag
// proof: a nok8s build never registers "kubernetes", so New() returns the
// clear "not available in this build" error instead of silently constructing
// an engine whose underlying client-go dependency was never linked in. Unlike
// noaws/noazure/nogcp, nok8s is not part of the supported AIR-GAPPED profile
// (Kubernetes stays in air-gapped builds per ADR-109's open-questions
// decision) — it exists for completeness, same rationale as connect's
// novault.
func TestNoK8sBuild_KubernetesNotAvailable(t *testing.T) {
	eng, err := New("kubernetes", false, false)
	if err == nil || eng != nil {
		t.Fatalf("New(\"kubernetes\") in a nok8s build: expected a non-nil error and nil engine; got eng=%v err=%v", eng, err)
	}
	if !strings.Contains(err.Error(), "not available in this build") {
		t.Errorf("expected error to say \"not available in this build\", got: %v", err)
	}
	if !strings.Contains(err.Error(), "kubernetes") {
		t.Errorf("expected error to name the backend \"kubernetes\", got: %v", err)
	}
}

// TestNoK8sBuild_OtherCloudEnginesStillRegistered proves nok8s excludes ONLY
// kubernetes among the cloud-IAM backends.
func TestNoK8sBuild_OtherCloudEnginesStillRegistered(t *testing.T) {
	for _, backendType := range []string{"aws-sts", "gcp", "azure"} {
		if _, err := New(backendType, false, false); err != nil {
			t.Errorf("New(%q) in a nok8s build: expected no error (nok8s must not exclude it), got %v", backendType, err)
		}
	}
}
