- **INV-GRPC-h2-abuse-responsive** Abusive HTTP/2 frames on one connection cannot wedge
  the server for others: against the real HTTP listener (fuzz) and the gRPC server
  (deterministic test), a connection replaying rapid stream open+reset, SETTINGS/PING
  floods, oversized HEADER blocks (HEADERS+CONTINUATION above the advertised header-list
  limit), CONTINUATION floods, stray WINDOW_UPDATE/DATA/GOAWAY, or (gRPC) opening past
  MAX_CONCURRENT_STREAMS must not panic the server, and after it the server still
  answers a normal request on an independent connection. Why: CVE-2023-39325-class
  HTTP/2 abuse (rapid reset, continuation/settings floods) is a well-known remote-DoS
  surface; the gRPC listener's own h2 ceilings (`MaxConcurrentStreams` 128,
  `MaxHeaderListSize` 64 KiB, keepalive enforcement) are Keyorix-set
  (`server/grpc/server.go`), while the REST listener relies on net/http's auto-h2 stdlib
  defaults plus the Go-runtime rapid-reset mitigation. Guard:
  `server/http2_abuse_fuzz_test.go:FuzzHTTP2AbusiveFrames` (HTTP, fuzz; built with
  `newHTTPServer`) and `server/grpc/http2_abuse_test.go:TestHTTP2Abuse_ServerStaysResponsive`
  (gRPC); the Keyorix-set SETTINGS are additionally pinned by
  `connection_limits_test.go:TestNewServer_AdvertisesStreamAndHeaderLimits`. A recovered
  panic does not crash the process (net/http / x/net/http2 log `panic serving` to
  `ErrorLog` and reset the connection), so the REST no-panic oracle reads that log via
  `panicLog`; it is proven able to fire by
  `server/fuzz_harness_oracles_test.go:TestHTTP2AbuseHarness_DetectsServerPanic`. That the
  oversized-header and CONTINUATION ops really exceed the limit for every selecting byte,
  and that the live server does not answer the former with a 204, is pinned by
  `TestHTTP2AbuseOps_ReachTheirLimit`. Red-proofed by a wedged (blocking) handler firing
  the responsiveness oracle. Not covered: heap bytes are not measured directly
  (responsiveness is the proxy); goroutine counts are only checked once after the corpus
  as a coarse backstop (not per input, not red-proofed); the gRPC test runs plaintext h2c,
  so the gRPC TLS path is not covered.
