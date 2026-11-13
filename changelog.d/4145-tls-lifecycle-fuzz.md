### Testing
- **TLS termination & certificate-lifecycle fuzzing.** Added three fuzz harnesses
  covering the HTTP TLS listener (plus a gRPC h2c abuse test): `FuzzReloaderFailClosed`
  (`internal/tlsreload`) drives the certificate reloader through valid/expired/
  not-yet-valid/mismatched/half-rotated/truncated/empty/deleted/symlink-swapped
  cert-key file states and asserts it never serves a cert/key mismatch, never an
  empty config, and always keeps the previous good certificate on a bad reload;
  `FuzzTLSHandshakeHostileClientHello` (`server`) throws hostile ClientHello bytes
  at a real hardened HTTPS listener and asserts no recovered panic (read from the
  server's `ErrorLog`, since net/http recovers connection panics), fail-closed
  connection close within the read deadline, and that failed handshakes never reach the HTTP
  handler; `FuzzHTTP2AbusiveFrames` (`server`) plus
  `TestHTTP2Abuse_ServerStaysResponsive` (`server/grpc`) throw abusive HTTP/2
  frames (rapid reset, SETTINGS/PING floods, oversized headers above the header-list
  limit, CONTINUATION floods) at the real HTTP and gRPC servers and assert they stay
  responsive; the harnesses' panic oracles and the abuse ops' reach are self-tested.
