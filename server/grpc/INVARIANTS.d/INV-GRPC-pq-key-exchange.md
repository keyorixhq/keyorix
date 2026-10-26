- **INV-GRPC-pq-key-exchange** No TLS listener config (gRPC `createGRPCTLSConfig`, HTTP
  `createTLSConfig`, AutoCert) sets `tls.Config.CurvePreferences`, and no image or chart sets
  `GODEBUG=tlsmlkem=0`, so Go's default groups apply and a current client negotiates the
  hybrid `X25519MLKEM768`; a client without the hybrid still connects. Why: RD-PQTLS-1: the
  post-quantum key exchange is inherited from Go's defaults and is lost silently by a
  well-meaning "hardening" that pins curves. Guard:
  `pq_transport_test.go:TestNewServer_TLS_NegotiatesX25519MLKEM768` and
  `TestCreateGRPCTLSConfig_DoesNotSetCurvePreferences` (gRPC),
  `server/pq_transport_test.go:TestPQTransport_HTTP_DefaultMode_NegotiatesX25519MLKEM768`
  and `TestPQTransport_HTTP_ListenerDoesNotSetCurvePreferences` (HTTP). Not covered: an
  environment that sets `GODEBUG=tlsmlkem=0` outside the repo, and TLS terminated by a proxy.
  The key exchange only: certificates and signatures stay classical
  (`docs/post-quantum-transport.md`).
