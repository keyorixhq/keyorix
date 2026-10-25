### Added
- **Post-quantum key exchange is verified and observable.** The HTTP and gRPC listeners and
  the CLI already negotiate the hybrid `X25519MLKEM768` TLS key exchange (Go's default; nothing
  in Keyorix narrows it). New integration tests assert the negotiated group on a real handshake
  and fail if a listener ever sets `CurvePreferences`. The server counts handshakes in
  `keyorix_tls_handshakes_total{listener,group}`, and `keyorix doctor` shows the group
  (`key_exchange` and `post_quantum_key_exchange` fields in its TLS report; existing fields
  are unchanged). Only the key exchange is post-quantum, not certificates or signatures.
  See `docs/post-quantum-transport.md` for how to verify with `openssl`, the
  `GODEBUG=tlsmlkem=0` revert switch and the behaviour under Go's FIPS 140-3 mode.
