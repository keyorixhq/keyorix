- **INV-GRPC-streaming-rpc** Server-streaming and bidi-streaming RPCs must satisfy
  three safety invariants for all callers and all wire inputs:
  (stream-auth) an unauthenticated or unauthorized caller never receives a data frame
  before the stream closes with an error — data flow must be gated behind the auth
  check; (stream-no-panic) no panic-shaped error reaches the client for any
  grammatically or syntactically mutated first message: `codes.Unknown` (an unmapped
  error), a non-status error, or a `codes.Internal` whose message looks like a raw
  internal error (`classifyStatusLeak`) is fatal, while a clean `codes.Internal` is
  tolerated and only logged (see HARDENING-2 below); (stream-bounded) an unauthorized
  caller's stream must close with an error rather than hang: `DeadlineExceeded` for the
  zero-grant caller within the 10 s hang-detector deadline is fatal (a denied stream
  normally closes in milliseconds). Additionally, a `codes.Internal` or `codes.Unknown`
  on malformed wire bytes is a HARDENING finding, logged and not fatal (HARDENING-2;
  better practice: codes.InvalidArgument — same class as HARDENING-1 for unary RPCs in
  PBG1). Guard:
  `server/grpc/grpc_existence_streaming_fuzz_test.go:FuzzGRPCStreamingRPCs`
  (item #9), registered in
  `scripts/fuzzing/targets.d/server-grpc__FuzzGRPCStreamingRPCs.conf`.
  Also covers: ResGuard heap oracle for streaming RPCs (fixed 10000× threshold, same
  LEFTOVER caveat as INV-GRPC-existence-oracle). Not covered: long-lived authorized
  streams (the admin stream is cancelled after 2s); per-frame re-authorization;
  backpressure; bidi-streaming (none registered in the current server).
