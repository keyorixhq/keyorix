- **INV-GRPC-tls-handshake-failclosed** Both TLS listeners (HTTP and gRPC share the
  `applyTLSHardening` posture) fail closed on a hostile or malformed ClientHello: the
  server never panics on attacker-controlled handshake bytes (truncated/oversized TLS
  records, SNI/ALPN/session-ticket/renegotiation shapes, plaintext sent to a TLS port,
  garbage), it closes a connection that never completes a handshake within its read
  deadline rather than holding it (slowloris), and no bytes from a failed handshake are
  ever handed to the HTTP handler. Why: a TLS termination point that panicked, hung, or
  leaked pre-handshake bytes to the application on bad input would be a remote DoS or a
  request-smuggling surface; crypto/tls is expected to reject bad input with an error,
  and the listener's `ReadHeaderTimeout`/`ReadTimeout` (newHTTPServer) bound the
  handshake. Guard: `server/tls_handshake_fuzz_test.go:FuzzTLSHandshakeHostileClientHello`
  (real hardened listener on loopback; red-proofed by removing the handshake read
  deadline). Not covered: it does not complete a real TLS session (no client-side
  crypto), so post-handshake application behaviour is out of scope here.
