- **INV-GRPC-existence-oracle** ADR-096 §4 (gRPC anti-enumeration rule): for every
  unary RPC whose request descriptor has a primary uint32 field named "id" exactly, a
  caller without global permission must receive `codes.PermissionDenied` for BOTH a
  known-existing resource ID and a known-non-existing resource ID. A
  `codes.PermissionDenied` vs `codes.NotFound` difference lets an unauthorized caller
  probe resource existence and is a VULNERABILITY. The narrow exception (a globally-
  privileged caller gets `codes.NotFound` for a truly non-existing target) is
  correctly handled by `authorizeScopedTarget` (server/grpc/services/conversions.go:160)
  and is NOT tested here (to avoid false positives). Unauthenticated callers must also
  receive the same code for both IDs (the auth interceptor rejects before any ID
  lookup). Guard: `server/grpc/grpc_existence_streaming_fuzz_test.go:FuzzGRPCExistenceOracle`
  (item #8), registered in
  `scripts/fuzzing/targets.d/server-grpc__FuzzGRPCExistenceOracle.conf`.
  Also covers: ResGuard heap oracle (fixed allocation-amplification threshold 10000×;
  not yet calibrated via resguard.Budget — LEFTOVER). Not covered: RPCs with `_id`
  suffix fields (qualifier/filter fields, not primary resource IDs); timing
  side-channels (ADR-096 §"Explicitly deferred"); globally-privileged caller exception;
  string-typed IDs; RPCs that do not address a single resource by primary ID.
