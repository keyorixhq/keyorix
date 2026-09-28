//go:build novault && !noaws && !noazure && !nogcp

package connect

import "testing"

// TestNoVaultBuild_VaultNotRegistered is B1 (ADR-109 step 6, S2)'s per-tag
// registry proof for the completeness tag novault (see vault_register.go's
// doc comment: no AIR-GAPPED profile excludes Vault, but the combination
// must still compile and be testable in isolation).
func TestNoVaultBuild_VaultNotRegistered(t *testing.T) {
	conn, ok := NewCloudConnector("vault", ConnectorParams{Name: "wiring-test"})
	if ok || conn != nil {
		t.Fatalf("NewCloudConnector(\"vault\") in a novault build: expected ok=false, nil connector; got ok=%v conn=%v", ok, conn)
	}
}

// TestNoVaultBuild_OtherConnectorsStillRegistered proves novault excludes
// ONLY vault.
func TestNoVaultBuild_OtherConnectorsStillRegistered(t *testing.T) {
	for _, connectorType := range []string{"aws-secrets-manager", "gcp-secret-manager", "azure-key-vault"} {
		if _, ok := NewCloudConnector(connectorType, ConnectorParams{Name: "wiring-test"}); !ok {
			t.Errorf("NewCloudConnector(%q) in a novault build: expected ok=true (novault must not exclude it)", connectorType)
		}
	}
}
