package healthscan

import (
	"context"
	"testing"
)

func TestCheckTTLHygiene_FlagsZeroAndOverLong(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/mounts": `{"data":{"secret/":{"type":"kv","config":{"default_lease_ttl":0,"max_lease_ttl":0}}}}`,
		"/v1/sys/auth":   `{"data":{"token/":{"type":"token","config":{"default_lease_ttl":3000000,"max_lease_ttl":3000000}}}}`,
	})
	res := checkTTLHygiene(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityMedium {
		t.Fatalf("expected medium, got %+v", res)
	}
}

func TestCheckTTLHygiene_Bounded(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/mounts": `{"data":{"secret/":{"type":"kv","config":{"default_lease_ttl":3600,"max_lease_ttl":7200}}}}`,
		"/v1/sys/auth":   `{"data":{"token/":{"type":"token","config":{"default_lease_ttl":3600,"max_lease_ttl":7200}}}}`,
	})
	res := checkTTLHygiene(context.Background(), c)
	if res.Finding == nil || res.Finding.Severity != SeverityInfo {
		t.Fatalf("expected info for bounded TTLs, got %+v", res)
	}
}

func TestCheckLeaseCounts_BestEffort(t *testing.T) {
	c, _ := fakeServer(t, map[string]string{
		"/v1/sys/mounts":                  `{"data":{"secret/":{"type":"kv"},"database/":{"type":"database"}}}`,
		"/v1/sys/leases/lookup/database/": `{"data":{"keys":["a","b"]}}`,
	})
	res := checkLeaseCounts(context.Background(), c)
	if res.Finding == nil {
		t.Fatal("expected a finding")
	}
}
