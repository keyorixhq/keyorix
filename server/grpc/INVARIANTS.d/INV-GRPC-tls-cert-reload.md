- **INV-GRPC-tls-cert-reload** The gRPC and HTTP TLS listeners serve their certificate
  through `internal/tlsreload` (`tls.Config.GetCertificate`), never a pair pinned at
  start: a cert/key pair rotated on disk reaches the next handshake within
  `tlsreload.CheckInterval` (a change is detected by a content hash of the cert and key
  files, not by file times, so `cp -p`, `rsync -t` and a restore from backup are picked
  up), a rotated pair that does not load leaves the previous one
  in service, and an unloadable pair at start still refuses to start. Both use
  `config.DefaultCipherSuites`, which covers ECDSA as well as RSA certificates for
  TLS 1.2. Why: HARDEN-HTTP-1: both listeners pinned the start-up pair until a restart,
  and the RSA-only suite list failed every TLS 1.2 handshake for an ECDSA certificate.
  Guard: `tls_reload_test.go:TestNewServer_TLS_ECDSAOverTLS12_H2_AndCertReload`,
  `server/tls_reload_ecdsa_test.go:TestStartHTTPServer_TLSReloadsRotatedCertificateAndNegotiatesH2`,
  `internal/tlsreload/tlsreload_test.go` (including
  `TestReloader_PicksUpReplacementWithPreservedMtime` and
  `TestReloader_UnchangedPairIsNotReloaded`), and
  `internal/tlsreload/reloader_failclosed_fuzz_test.go:FuzzReloaderFailClosed` (fuzzes
  valid/expired/not-yet-valid/mismatched/half-rotated/truncated/empty/deleted/symlink
  file-state sequences against a stdlib-loader differential: a cert/key mismatch is never
  served and the previous good pair is always retained on a bad reload). Not covered: an
  open gRPC connection keeps its certificate until `max_connection_age` recycles it.
