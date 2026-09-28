package healthscan

import (
	"context"
	"testing"
)

func TestCheckTLSListener_Disabled(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/config/state/sanitized": `{"data":{"listeners":[{"config":{"tls_disable":true}}]}}`,
	})
	res := checkTLSListener(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityCritical {
		t.Fatalf("expected critical for tls_disable=true, got %+v", res)
	}
}

func TestCheckTLSListener_WeakVersion(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/config/state/sanitized": `{"data":{"listeners":[{"config":{"tls_disable":false,"tls_min_version":"tls10"}}]}}`,
	})
	res := checkTLSListener(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityMedium {
		t.Fatalf("expected medium for tls_min_version=tls10, got %+v", res)
	}
}

func TestCheckTLSListener_Good(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/config/state/sanitized": `{"data":{"listeners":[{"config":{"tls_disable":false,"tls_min_version":"tls12"}}]}}`,
	})
	res := checkTLSListener(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityInfo {
		t.Fatalf("expected info for tls12, got %+v", res)
	}
}
