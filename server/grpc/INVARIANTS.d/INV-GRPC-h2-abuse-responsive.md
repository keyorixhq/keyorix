- **INV-GRPC-h2-abuse-responsive** Abusive HTTP/2 frames on one connection cannot wedge
  the server for others: against both the real HTTP and gRPC listeners, a connection
  replaying rapid stream open+reset, SETTINGS/PING floods, oversized HEADER blocks,
  CONTINUATION floods, stray WINDOW_UPDATE/DATA/GOAWAY, or opening past
  MAX_CONCURRENT_STREAMS must not panic the server, and after it the server still
  answers a normal request on an independent connection with bounded goroutines. Why:
  CVE-2023-39325-class HTTP/2 abuse (rapid reset, continuation/settings floods) is a
  well-known remote-DoS surface; the gRPC listener's own h2 ceilings
  (`MaxConcurrentStreams` 128, `MaxHeaderListSize` 64 KiB, keepalive enforcement) are
  Keyorix-set (`server/grpc/server.go`), while the REST listener relies on net/http's
  auto-h2 stdlib defaults plus the Go-runtime rapid-reset mitigation. Guard:
  `server/http2_abuse_fuzz_test.go:FuzzHTTP2AbusiveFrames` (HTTP, fuzz) and
  `server/grpc/http2_abuse_test.go:TestHTTP2Abuse_ServerStaysResponsive` (gRPC); the
  Keyorix-set SETTINGS are additionally pinned by
  `connection_limits_test.go:TestNewServer_AdvertisesStreamAndHeaderLimits`. Red-proofed
  by a wedged (blocking) handler firing the responsiveness oracle. Not covered: heap
  bytes are not measured directly (goroutine count + responsiveness are the proxies).
