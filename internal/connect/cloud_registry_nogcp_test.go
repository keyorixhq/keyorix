//go:build nogcp && !noaws && !noazure && !novault

package connect

import "testing"

// TestNoGCPBuild_GCPSecretManagerNotRegistered is B1 (ADR-109 step 6, S2)'s
// per-tag registry proof: a nogcp build never registers "gcp-secret-manager",
// so connect.NewCloudConnector reports not-found instead of silently
// constructing a connector whose underlying GCP SDK was never linked in.
func TestNoGCPBuild_GCPSecretManagerNotRegistered(t *testing.T) {
	conn, ok := NewCloudConnector("gcp-secret-manager", ConnectorParams{Name: "wiring-test"})
	if ok || conn != nil {
		t.Fatalf("NewCloudConnector(\"gcp-secret-manager\") in a nogcp build: expected ok=false, nil connector; got ok=%v conn=%v", ok, conn)
	}
}

// TestNoGCPBuild_OtherConnectorsStillRegistered proves nogcp excludes ONLY
// gcp-secret-manager.
func TestNoGCPBuild_OtherConnectorsStillRegistered(t *testing.T) {
	for _, connectorType := range []string{"aws-secrets-manager", "azure-key-vault", "vault"} {
		if _, ok := NewCloudConnector(connectorType, ConnectorParams{Name: "wiring-test"}); !ok {
			t.Errorf("NewCloudConnector(%q) in a nogcp build: expected ok=true (nogcp must not exclude it)", connectorType)
		}
	}
}
