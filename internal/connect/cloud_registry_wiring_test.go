//go:build !noaws && !noazure && !nogcp && !novault

package connect

import "testing"

// TestFullBuildRegistersEveryCloudConnector is the S1 "no behaviour change
// for the default (full) build" proof (ADR-109 step 6): it asserts
// NewCloudConnector resolves every connector type a pre-step-6 origin/main's
// wireConnect resolved by calling its constructor directly (aws-secrets-manager,
// gcp-secret-manager, azure-key-vault, vault), now via the cloudConnectors
// registry those backends' own init()s populate. A regression here means
// either a backend stopped registering itself, or the registry lookup broke —
// either way, the full build silently lost a connector type it used to have.
func TestFullBuildRegistersEveryCloudConnector(t *testing.T) {
	want := []string{"aws-secrets-manager", "gcp-secret-manager", "azure-key-vault", "vault"}
	for _, connectorType := range want {
		t.Run(connectorType, func(t *testing.T) {
			conn, ok := NewCloudConnector(connectorType, ConnectorParams{Name: "wiring-test"})
			if !ok {
				t.Fatalf("NewCloudConnector(%q) in the full build: expected ok=true", connectorType)
			}
			if conn == nil {
				t.Fatalf("NewCloudConnector(%q) in the full build: expected a non-nil connector", connectorType)
			}
			if conn.Type() != connectorType {
				t.Fatalf("NewCloudConnector(%q).Type() = %q, want %q", connectorType, conn.Type(), connectorType)
			}
		})
	}
	if got := len(cloudConnectors); got != len(want) {
		t.Fatalf("cloudConnectors has %d entries, want exactly %d (%v) — a full build must register precisely these, no more, no fewer", got, len(want), want)
	}
}
