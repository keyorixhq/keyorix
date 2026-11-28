- **INV-GRPC-existence-oracle** ADR-096 §4 (gRPC anti-enumeration rule): for every
  unary RPC whose request descriptor has a primary uint32 field named "id" exactly, a
  caller without global permission must get the SAME answer, identical gRPC status code
  AND identical status message, for a known-existing resource ID and for the non-existing
  ID 999999. The harness calls the RPC twice with the same body and the same caller and
  fails on ANY difference (`existenceDiff`): PermissionDenied vs NotFound, OK vs NotFound,
  or the same code with a different message. An ID of the wrong resource type does not
  exist for that RPC either, so it must get the same answer as 999999. The same rule is
  checked for unauthenticated callers (the auth interceptor rejects before any ID lookup).
  This does not require PermissionDenied: an RPC may validate the request before
  authorization (`DynamicSecretService/UpdateConfigAdminDSN` answers `InvalidArgument` for
  both IDs today), as long as both IDs get the same answer. The narrow exception (a
  globally-privileged caller gets `codes.NotFound` for a truly non-existing target) is
  correctly handled by `authorizeScopedTarget` (server/grpc/services/conversions.go:160)
  and is NOT tested here. Guard:
  `server/grpc/grpc_existence_streaming_fuzz_test.go:FuzzGRPCExistenceOracle`
  (item #8; `TestExistenceDiff` pins the comparison), registered in
  `scripts/fuzzing/targets.d/server-grpc__FuzzGRPCExistenceOracle.conf`.
  Also covers: ResGuard heap oracle (fixed allocation-amplification threshold 10000×,
  logged as RESOURCE-AMP, not asserted; not yet calibrated via resguard.Budget —
  LEFTOVER). Not covered: RPCs with `_id` suffix fields (qualifier/filter fields, not
  primary resource IDs); timing side-channels (ADR-096 §"Explicitly deferred");
  globally-privileged caller exception; string-typed IDs; RPCs that do not address a
  single resource by primary ID; a per-resource-type map of known IDs (the known IDs are
  not typed per RPC, so some pairs compare two missing IDs).
