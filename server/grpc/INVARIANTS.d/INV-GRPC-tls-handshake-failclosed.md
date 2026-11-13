- **INV-GRPC-tls-handshake-failclosed** The HTTP TLS listener (built on the
  `applyTLSHardening` posture that the gRPC listener shares) fails closed on a hostile or
  malformed ClientHello: the server never panics on attacker-controlled handshake bytes
  (truncated/oversized TLS records, SNI/ALPN/session-ticket/renegotiation shapes,
  plaintext sent to a TLS port, garbage), it closes a connection that never completes a
  handshake within its read deadline rather than holding it (slowloris), and no bytes from
  a failed handshake are ever handed to the HTTP handler. Why: a TLS termination point that
  panicked, hung, or leaked pre-handshake bytes to the application on bad input would be a
  remote DoS or a request-smuggling surface; crypto/tls is expected to reject bad input
  with an error, and the listener's `ReadHeaderTimeout`/`ReadTimeout` (newHTTPServer,
  pinned by `server/http_server_test.go:TestNewHTTPServer_Timeouts`) bound the handshake.
  Guard: `server/tls_handshake_fuzz_test.go:FuzzTLSHandshakeHostileClientHello` (an
  `http.Server` with short 2s timeouts serving the hardened `createTLSConfig` on loopback).
  net/http recovers a handshake-goroutine panic, logs `http: panic serving` and closes the
  connection, so the no-panic oracle reads that line from the server's `ErrorLog`
  (`panicLog`), not a process crash; it is proven able to fire by
  `TestHostileClientHelloHarness_DetectsServerPanic` (a panicking `GetCertificate`). Not
  covered: it does not complete a real TLS session (no client-side crypto), so
  post-handshake application behaviour is out of scope; the gRPC TLS handshake is not
  driven (only the shared hardening is unit-tested); the closing-within-deadline oracle
  was red-proofed by removing the harness's own read deadline, not the production timeouts.
