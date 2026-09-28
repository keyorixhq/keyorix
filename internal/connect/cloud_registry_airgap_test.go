//go:build noaws && noazure && nogcp

package connect

import "testing"

// TestAirgapProfile_NoCloudConnectorsRegistered proves the ADR-109 step 6
// AIR-GAPPED profile (noaws,noazure,nogcp together — the exact tag set
// B2/B3's `make build-server-airgap` compiles with) excludes every cloud
// connector at once, while vault — which stays in air-gapped per ADR-109's
// open-questions decision (on-prem Vault read-through is a legitimate
// air-gapped use) — remains registered.
func TestAirgapProfile_NoCloudConnectorsRegistered(t *testing.T) {
	for _, connectorType := range []string{"aws-secrets-manager", "azure-key-vault", "gcp-secret-manager"} {
		if _, ok := NewCloudConnector(connectorType, ConnectorParams{Name: "wiring-test"}); ok {
			t.Errorf("NewCloudConnector(%q) in the air-gapped profile: expected ok=false", connectorType)
		}
	}
	if _, ok := NewCloudConnector("vault", ConnectorParams{Name: "wiring-test"}); !ok {
		t.Error("NewCloudConnector(\"vault\") in the air-gapped profile: expected ok=true (vault stays air-gapped)")
	}
	if got := len(cloudConnectors); got != 1 {
		t.Fatalf("cloudConnectors has %d entries in the air-gapped profile, want exactly 1 (vault)", got)
	}
}
