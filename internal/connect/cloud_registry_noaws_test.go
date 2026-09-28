//go:build noaws && !noazure && !nogcp && !novault

package connect

import "testing"

// TestNoAWSBuild_AWSSecretsManagerNotRegistered is B1 (ADR-109 step 6, S2)'s
// per-tag registry proof: a noaws build never registers "aws-secrets-manager",
// so connect.NewCloudConnector reports not-found instead of silently
// constructing a connector whose underlying AWS SDK was never linked in.
// server/main.go's wireConnect turns this ok=false into a startup failure
// naming the connector and the noaws build tag (see
// server/connect_failclosed_noaws_test.go).
func TestNoAWSBuild_AWSSecretsManagerNotRegistered(t *testing.T) {
	conn, ok := NewCloudConnector("aws-secrets-manager", ConnectorParams{Name: "wiring-test"})
	if ok || conn != nil {
		t.Fatalf("NewCloudConnector(\"aws-secrets-manager\") in a noaws build: expected ok=false, nil connector; got ok=%v conn=%v", ok, conn)
	}
}

// TestNoAWSBuild_OtherConnectorsStillRegistered proves noaws excludes ONLY
// aws-secrets-manager — a build tag that accidentally excluded a sibling
// connector would otherwise pass the negative test above for the wrong
// reason.
func TestNoAWSBuild_OtherConnectorsStillRegistered(t *testing.T) {
	for _, connectorType := range []string{"gcp-secret-manager", "azure-key-vault", "vault"} {
		if _, ok := NewCloudConnector(connectorType, ConnectorParams{Name: "wiring-test"}); !ok {
			t.Errorf("NewCloudConnector(%q) in a noaws build: expected ok=true (noaws must not exclude it)", connectorType)
		}
	}
}
