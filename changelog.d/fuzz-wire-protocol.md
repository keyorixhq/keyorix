### Testing
- **Wire-protocol fuzzing of the server transport (B1).** New `server/wirefuzz`
  package stands the real stack (router + auth middleware + handlers + core +
  storage, and the real gRPC server with its full interceptor chain) up in-process
  on loopback listeners and feeds RAW bytes to the production HTTP/1.1 parser, the
  HTTP/2 framer and the gRPC message framing — surface no existing fuzzer reached
  (they all drive `router.ServeHTTP` via `httptest`, bypassing the wire). Targets:
  `FuzzWireHTTP1` (request-line/Host/CL-vs-TE/chunk/trailer/pipeline/obs-fold
  framing with a body-embedded smuggling canary), `FuzzWireHTTP2` (pseudo-header
  abuse, CONTINUATION chains, RST/SETTINGS/PRIORITY/WINDOW_UPDATE abuse) and
  `FuzzWireGRPCFraming` (length-prefix abuse incl. a 4 GiB pre-alloc DoS probe).
  Oracles — no panic/hang/bounded allocation, handler-count smuggling (dispatches
  ≤ top-level requests, body-embedded canary never dispatched), authz/leak
  invariance (a secret's plaintext appears only with an authorizing credential on
  the wire), and no response splitting — are red/green proven in
  `oracle_redproof_test.go`. Declared in `scripts/fuzzing/targets.d/`.
- **Wire-fuzz: post-abuse health oracle + TLS/ALPN HTTP/2 target.** Added a
  per-connection health check to all wire targets — after each abusive input a
  FRESH connection must still be served (closing the single-connection gap the
  B1 report named as a caveat) — and a new `FuzzWireHTTP2TLS` target that serves
  the real REST router over TLS with ALPN "h2", reaching net/http's OWN HTTP/2
  server (a distinct framing path from grpc-go's, and the HTTP/2-on-the-HTTP-
  listener surface the earlier targets could not reach). Both are red/green proven
  (`TestRedProof_HTTPHealthProbe`, `TestRedProof_GRPCHealthProbe`,
  `TestRedProof_TLSHealthProbe`, `TestRedProof_TLSALPNReachability`, the last
  including an anti-vacuity check that h2 is actually negotiated).
