### Added
- **Hostile-server fuzz harnesses for the AWS SDK v2 and Azure Key Vault clients.**
  `fuzz/thirdparty/aws` and `fuzz/thirdparty/azure` drive the SDK clients behind the cloud
  connectors against fake endpoints that answer with hostile bodies, headers and status codes,
  and check that the client returns an error instead of panicking or hanging. The Azure harness
  includes a verified reproducer for a malformed `WWW-Authenticate` challenge panic reported
  upstream (Azure/azure-sdk-for-go#28004).
