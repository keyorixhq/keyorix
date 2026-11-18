- **INV-GRPC-streaming-rpc** Server-streaming and bidi-streaming RPCs must satisfy
  three safety invariants for all callers and all wire inputs:
  (stream-auth) an unauthenticated or unauthorized caller never receives a data frame
  before the stream closes with an error — data flow must be gated behind the auth
  check; (stream-no-panic) no panic-shaped error code (codes.Internal with a panic
  stack trace or codes.Unknown from an unhandled error) reaches the client for any
  grammatically or syntactically mutated first message; (stream-bounded) an
  unauthorized caller's stream must close within 2 seconds — the server must not
  spin on an unauthorized stream. Additionally, `codes.Internal` from the server on
  malformed wire bytes is a HARDENING finding (HARDENING-2; better practice:
  codes.InvalidArgument — same class as HARDENING-1 for unary RPCs in PBG1). Guard:
  `server/grpc/grpc_existence_streaming_fuzz_test.go:FuzzGRPCStreamingRPCs`
  (item #9), registered in
  `scripts/fuzzing/targets.d/server-grpc__FuzzGRPCStreamingRPCs.conf`.
  Also covers: ResGuard heap oracle for streaming RPCs (fixed 10000× threshold, same
  LEFTOVER caveat as INV-GRPC-existence-oracle). Not covered: long-lived authorized
  streams (all streams cancelled after 2s); per-frame re-authorization; backpressure;
  bidi-streaming (none registered in the current server).
