- **INV-CONNECT-backend-dial-guard** Every Connect HTTP backend dials through the
  link-local-refusing `connectGuardedDialer` that `newConnectHardenedTransport` installs:
  the client `NewVaultConnector` builds, `azureKVHTTPClient` (the client azurekv.go hands
  to azsecrets) and `awsSMHTTPClient` (the client awssm.go installs in the SDK). A backend
  that passes its bare base transport to its SDK is unguarded even though every netutil
  test stays green. New HTTP backends build their client in a function of the same shape
  and get a target in `egress_site_fuzz_test.go`. Why: V7-GAP-1 egress inventory
  (`docs/security/egress-inventory.md`, S12-S14). Guard:
  `FuzzConnectVaultTransportEgressParity`, `FuzzConnectAzureTransportEgressParity`,
  `FuzzConnectAWSTransportEgressParity`.
