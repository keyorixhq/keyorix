// cloud_registry.go — the registration seam for connect backends whose
// implementation touches a cloud SDK (ADR-109 step 6): aws-secrets-manager,
// azure-key-vault and gcp-secret-manager each register themselves from an
// init() in their own file, guarded by that integration's //go:build !no<x>
// tag, so a no<x> build's binary never links the corresponding SDK. vault has
// no cloud SDK dependency of its own (see vault.go's doc comment) — it still
// gets a registration entry (vault_register.go/vault_register_novault.go) for
// completeness (the novault tag exists so an unsupported combination still
// compiles and is testable), not because any AIR-GAPPED profile excludes it.
package connect

import "fmt"

// ConnectorParams are the constructor parameters for a registered connector.
// Not every field applies to every backend; each registered constructor reads
// only the ones it needs.
type ConnectorParams struct {
	Name        string
	Region      string
	AccountID   string
	ProjectID   string
	Address     string
	Token       string
	AllowedRefs []string
}

type cloudConnectorCtor func(ConnectorParams) Connector

// cloudConnectors holds the connectors registered by the current build.
var cloudConnectors = map[string]cloudConnectorCtor{}

// registerCloudConnector panics on a duplicate connector type — every
// registration happens from this package's own init()s, and a collision
// there is a build-time programming error, not a runtime condition to handle
// gracefully.
func registerCloudConnector(connectorType string, ctor cloudConnectorCtor) {
	if _, exists := cloudConnectors[connectorType]; exists {
		panic(fmt.Sprintf("connect: duplicate connector registration for %q", connectorType))
	}
	cloudConnectors[connectorType] = ctor
}

// NewCloudConnector returns the connector for connectorType ("aws-secrets-manager",
// "azure-key-vault", "gcp-secret-manager" or "vault"), if the current build
// registers it. ok is false when the build excludes it (e.g. -tags noaws
// excludes "aws-secrets-manager") — callers that already switched on a
// literal connectorType string know at the call site that ok=false means
// exactly that, not "unknown type" (an unrecognised type never reaches this
// function; see connect.KnownTypes and server/main.go's wireConnect).
func NewCloudConnector(connectorType string, params ConnectorParams) (conn Connector, ok bool) {
	ctor, ok := cloudConnectors[connectorType]
	if !ok {
		return nil, false
	}
	return ctor(params), true
}
