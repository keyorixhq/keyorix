### Testing
- **Wire-level gRPC fuzzing (PBG1).** New fuzzer `FuzzGRPCProtobufGrammarWireInvariants`
  (item #7) augments the grammar-driven `FuzzGRPCProtoreflectInvariants` (item #6) with
  seven wire-level mutation modes that the descriptor-driven builder explicitly skips: wrong
  wire type for a known field, truncated varint/length, overlarge length prefix (2^31-1),
  duplicate field, invalid UTF-8 in string field, conflicting oneof members, and raw
  high-bit junk bytes. Adds oracle (c) — malformed wire bytes must yield a client-error
  code, classified HARDENING when the server returns codes.Internal instead of
  codes.InvalidArgument — and oracle (d) — idempotency for zero-grant identity. Companion
  byte-level baseline `FuzzGRPCByteLevelRaw` added for the coverage measurement. All targets
  registered in `scripts/fuzzing/targets.d/`; invariant fragment at
  `server/grpc/INVARIANTS.d/INV-GRPC-protobuf-grammar-wire.md`.
