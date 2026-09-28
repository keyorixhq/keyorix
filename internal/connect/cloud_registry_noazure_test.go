//go:build noazure && !noaws && !nogcp && !novault

package connect

import "testing"

// TestNoAzureBuild_AzureKeyVaultNotRegistered is B1 (ADR-109 step 6, S2)'s
// per-tag registry proof: a noazure build never registers "azure-key-vault",
// so connect.NewCloudConnector reports not-found instead of silently
// constructing a connector whose underlying Azure SDK was never linked in.
func TestNoAzureBuild_AzureKeyVaultNotRegistered(t *testing.T) {
	conn, ok := NewCloudConnector("azure-key-vault", ConnectorParams{Name: "wiring-test"})
	if ok || conn != nil {
		t.Fatalf("NewCloudConnector(\"azure-key-vault\") in a noazure build: expected ok=false, nil connector; got ok=%v conn=%v", ok, conn)
	}
}

// TestNoAzureBuild_OtherConnectorsStillRegistered proves noazure excludes
// ONLY azure-key-vault.
func TestNoAzureBuild_OtherConnectorsStillRegistered(t *testing.T) {
	for _, connectorType := range []string{"aws-secrets-manager", "gcp-secret-manager", "vault"} {
		if _, ok := NewCloudConnector(connectorType, ConnectorParams{Name: "wiring-test"}); !ok {
			t.Errorf("NewCloudConnector(%q) in a noazure build: expected ok=true (noazure must not exclude it)", connectorType)
		}
	}
}
