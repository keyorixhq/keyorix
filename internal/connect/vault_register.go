// vault_register.go — registers the vault connector (ADR-109 step 6). Unlike
// the aws/azure/gcp connectors, vault.go itself has no cloud SDK dependency
// (it talks to Vault's HTTP API directly — see vault.go's own doc comment),
// so there is nothing to drop from the binary and no need to exclude that
// file. The novault tag only controls REGISTRATION — for completeness (an
// unsupported combination must still compile) and so the fail-closed path is
// testable in isolation, not because any AIR-GAPPED profile excludes on-prem
// Vault.
//
//go:build !novault

package connect

func init() {
	registerCloudConnector("vault", func(p ConnectorParams) Connector {
		return NewVaultConnector(p.Name, p.Address, p.Token, p.AllowedRefs)
	})
}
