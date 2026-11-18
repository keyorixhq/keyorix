### Security

- Added existence-leak oracle (`FuzzGRPCExistenceOracle`) for all unary gRPC RPCs
  with a primary `id` field: verifies ADR-096 §4 (zero-grant and unauthenticated
  callers must receive the same gRPC error code for existing-but-denied and
  nonexistent resources). Red/green-proofed against a planted `codes.NotFound`
  defect in `authorizeScopedTarget`. Registry: `server-grpc__FuzzGRPCExistenceOracle`.

### Security

- Added streaming RPC harness (`FuzzGRPCStreamingRPCs`) for server-streaming gRPC
  RPCs: verifies unauthorized callers never receive data frames, streams close within
  bounds, and no panic-shaped errors occur. Grammar + 7 wire mutations. Red/green-
  proofed against a planted pre-auth `stream.Send`. Registry:
  `server-grpc__FuzzGRPCStreamingRPCs`.

### Changed

- Added ResGuard heap oracle to both new gRPC fuzz targets: allocation greater than
  10000× input size is logged as a RESOURCE-AMP finding. First finding:
  `ConnectService/DeleteRefGrant` at 1.26M× on 2-byte input (needs investigation).
