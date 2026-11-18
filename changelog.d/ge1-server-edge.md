### Testing
- **Fuzz the gRPC server edge: hostile metadata through the real interceptor chain.**
  New `FuzzGRPCEdgeAuthMetadata` (`server/grpc/interceptors`) drives fuzzed,
  hostile gRPC metadata — oversized / repeated / binary / odd-encoding
  authorization headers, malformed Bearer/PAT/session/machine-token forms, junk
  neighbour headers, and cancelled / past-deadline contexts — through the
  production-order unary interceptor chain (Recovery → Timeout → WriteContention →
  Auth → RateLimit → ShareElevationAudit) in front of a sentinel handler. Oracles
  (each red/green-proven in `edge_auth_metadata_redgreen_test.go` against the same
  `edgeViolation` predicate the fuzzer uses): no panic is ever caught by Recovery;
  a handler is reached if and only if a fully-resolved authenticated principal is
  on its context (no partial auth/ratelimit/audit evaluation); bounded work/memory
  via the shared `resguard` budget; no server secret or caller bearer-token echoed
  into the client error or the server log; every non-OK result is a well-formed
  fail-closed gRPC status. Registered in `scripts/fuzzing/targets.d/`.
- **Fuzz the shared httpx request decoder behind the real body-size cap.** New
  `FuzzHTTPXDecodeEdge` (`server/http/handlers/httpx`) drives hostile
  `(content-type, body)` — content-type confusion, charset tricks, trailing data,
  huge numbers, duplicate keys, unknown fields, deep nesting, invalid UTF-8, and
  oversized declared-length/chunked bodies — through `httpx.MustDecodeBody` behind
  `middleware.MaxBodyBytes`, with a sentinel business handler behind the decode.
  Non-duplicative of `FuzzJSONDecodeBoundedWork`: adds a leak guard on the
  decode-error response envelope, the fail-closed-through-the-cap invariant
  (handler reached iff decode succeeded), HTTP status discipline, and a `resguard`
  bounded-memory budget — each red/green-proven in `edge_decode_redgreen_test.go`.
