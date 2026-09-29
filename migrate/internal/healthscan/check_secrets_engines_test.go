package healthscan

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCheckSecretsEnginesInventory(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/mounts": `{"data":{
			"secret/":{"type":"kv","options":{"version":"2"}},
			"legacy/":{"type":"kv","options":{"version":"1"}},
			"database/":{"type":"database"},
			"cubbyhole/":{"type":"cubbyhole"}
		}}`,
	})
	res := checkSecretsEnginesInventory(context.Background(), c)
	if res.Finding == nil {
		t.Fatal("expected a finding")
	}
	if !strings.Contains(res.Finding.Evidence, "KV v1: 1") || !strings.Contains(res.Finding.Evidence, "KV v2: 1") {
		t.Errorf("evidence = %q, want KV v1: 1, KV v2: 1", res.Finding.Evidence)
	}
	if !strings.Contains(res.Finding.Evidence, "database/(database)") {
		t.Errorf("evidence = %q, want database/ flagged as a dynamic mount", res.Finding.Evidence)
	}
	if strings.Contains(res.Finding.Evidence, "cubbyhole/(cubbyhole)") {
		t.Errorf("evidence = %q, cubbyhole must not be counted as dynamic", res.Finding.Evidence)
	}
}

func TestCheckKVv2Config_FlagsNoCAS(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/mounts":    `{"data":{"secret/":{"type":"kv","options":{"version":"2"}}}}`,
		"/v1/secret/config": `{"data":{"max_versions":10,"cas_required":false}}`,
	})
	res := checkKVv2Config(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityLow {
		t.Fatalf("expected low severity for cas_required=false, got %+v", res)
	}
}

func TestCheckSecretStaleness_FlagsOldSecret(t *testing.T) {
	fresh := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/mounts":          `{"data":{"secret/":{"type":"kv","options":{"version":"2"}}}}`,
		"/v1/secret/metadata/":    `{"data":{"keys":["old","new"]}}`,
		"/v1/secret/metadata/old": `{"data":{"updated_time":"2020-01-01T00:00:00Z"}}`,
		"/v1/secret/metadata/new": `{"data":{"updated_time":"` + fresh + `"}}`,
	})
	res := checkSecretStaleness(context.Background(), c)
	if res.Finding == nil {
		t.Fatal("expected a finding")
	}
	if !strings.Contains(res.Finding.Evidence, "2 secrets inspected") || !strings.Contains(res.Finding.Evidence, "1 not updated") {
		t.Errorf("evidence = %q, want 2 inspected, 1 stale", res.Finding.Evidence)
	}
	if res.Finding.Severity != SeverityLow {
		t.Errorf("severity = %s, want low", res.Finding.Severity)
	}
}

// TestCheckSecretStaleness_NeverReadsDataPath is this check's own redaction proof: the fake
// server fails the test outright if anything ever GETs a /data/ path, not just /metadata/.
func TestCheckSecretStaleness_NeverReadsDataPath(t *testing.T) {
	fresh := time.Now().Format(time.RFC3339)
	mux := newCanaryMux(t, map[string]string{
		"/v1/sys/mounts":           `{"data":{"secret/":{"type":"kv","options":{"version":"2"}}}}`,
		"/v1/secret/metadata/":     `{"data":{"keys":["leaf"]}}`,
		"/v1/secret/metadata/leaf": `{"data":{"updated_time":"` + fresh + `"}}`,
	}, "/v1/secret/data/")
	c := mux
	checkSecretStaleness(context.Background(), c)
}
