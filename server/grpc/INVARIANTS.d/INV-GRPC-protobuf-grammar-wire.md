- **INV-GRPC-protobuf-grammar-wire** The gRPC server handles all syntactically
  malformed proto wire encodings without panicking and without an error-code leak:
  (a) no panic reaches the client for any wire input (covered jointly with
  INV-GRPC-04 oracle 1); (b) a zero-grant identity calling any RPC twice with the
  same raw bytes receives the same gRPC error code on both calls (idempotency;
  excluding DeadlineExceeded and ResourceExhausted — non-deterministic gRPC
  infrastructure codes under parallel load); (c)
  malformed bytes that cause proto.Unmarshal to fail currently return codes.Internal
  with the message "grpc: error unmarshalling request: ..." — a HARDENING gap noted
  in the PBG1 session report (better practice: codes.InvalidArgument), not a security
  defect; (d) the wire mutations that the descriptor-driven grammar builder
  explicitly avoids — wrong wire type for a known field, truncated varint, overlarge
  length prefix, duplicate field, invalid UTF-8 in string field, conflicting oneof
  members — are exercised by the companion wire-mutation target. Why: the grammar
  fuzzer (INV-GRPC-04) always produces valid proto and never exercises the
  proto.Unmarshal decode-failure path; a wire-level target is needed to cover that
  surface. Guard: `server/grpc/protobuf_grammar_wire_fuzz_test.go:FuzzGRPCProtobufGrammarWireInvariants`
  (item #7, oracles a/c/d), registered in
  `scripts/fuzzing/targets.d/server-grpc__FuzzGRPCProtobufGrammarWireInvariants.conf`.
  Not covered: streaming RPCs (same gap as INV-GRPC-04); allocation amplification
  (LEFTOVER pending resguard integration); existence leakage via ID substitution
  (LEFTOVER — oracle (d)'s idempotency check approximates it for the zero-grant
  identity).
