### Changed

- Added a gRPC existence-leak fuzz oracle (`FuzzGRPCExistenceOracle`) for all unary
  RPCs with a primary `id` field: verifies ADR-096 §4 (zero-grant and unauthenticated
  callers must receive the same gRPC error code for an existing-but-denied and a
  nonexistent resource). Test-only; no product code changed. Registry:
  `server-grpc__FuzzGRPCExistenceOracle`.
- Added a streaming RPC fuzz harness (`FuzzGRPCStreamingRPCs`) for server-streaming
  gRPC RPCs: verifies unauthorized callers never receive data frames, denied streams
  close rather than hang, and no panic-shaped errors occur. Grammar plus 7 wire
  mutations. Registry: `server-grpc__FuzzGRPCStreamingRPCs`.
- Both targets log (not assert) allocations greater than 10000x the input size as
  RESOURCE-AMP observations for review.
