### Testing
- **Wire-protocol fuzzing of the server transport (B1).** New `server/wirefuzz`
  package stands the real stack (router + auth middleware + handlers + core +
  storage, and the real gRPC server with its full interceptor chain) up in-process
  on loopback listeners and feeds RAW bytes to the production HTTP/1.1 parser, the
  HTTP/2 framers (grpc-go's and net/http's own, the latter over TLS with ALPN
  "h2") and the gRPC message framing — surface no existing fuzzer reached (they all
  drive `router.ServeHTTP` via `httptest`, bypassing the wire). Targets:
  `FuzzWireHTTP1` (a structured lane of fixed framing variants with a body-embedded
  smuggling canary, plus a raw lane where fuzz bytes become Content-Length deltas
  and odd forms, chunk-size tokens, line terminators, TE values, a raw header and a
  verbatim tail), `FuzzWireHTTP2` (pseudo-header abuse, CONTINUATION chains,
  RST/SETTINGS/PRIORITY/WINDOW_UPDATE abuse, valid gRPC bodies for either secret),
  `FuzzWireGRPCFraming` (length-prefix abuse incl. a 4 GiB pre-alloc probe, plus a
  valid-message shape) and `FuzzWireHTTP2TLS`. Oracles: no panic/hang/bounded
  allocation; handler-count smuggling and a never-dispatched body canary
  (HTTP/1 structured lane); per-request (HTTP/1) and per-stream (HTTP/2) authz/leak
  invariance, so a secret returned to a request or stream that carried no
  authorizing credential is caught even when another request on the same connection
  carried one; no response splitting on encoded CRLF payloads placed in reflectable
  positions; and a post-abuse health probe that makes a fresh connection complete a
  real request. Drivers never half-close before reading (a FIN makes net/http cancel
  the request, so every token-bearing request fails closed with 503 and the leak
  oracle would never see an authorized response). Each target has an anti-vacuity
  test (an admin read of A returns A, the projA reader's read of B is denied) and a
  planted-leak red twin through the same driver; every oracle predicate, the
  allocation oracle and the health probes (including a listener that accepts but
  never serves) have committed red/green proofs in `oracle_redproof_test.go` and
  `anti_vacuity_test.go`. Declared in `scripts/fuzzing/targets.d/`.
