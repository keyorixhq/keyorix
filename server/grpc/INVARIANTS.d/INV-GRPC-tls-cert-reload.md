- **INV-GRPC-tls-cert-reload** The gRPC and HTTP TLS listeners serve their certificate
  through `internal/tlsreload` (`tls.Config.GetCertificate`), never a pair pinned at
  start: a cert/key pair rotated on disk reaches the next handshake within
  `tlsreload.CheckInterval`, a rotated pair that does not load leaves the previous one
  in service, and an unloadable pair at start still refuses to start. Both use
  `config.DefaultCipherSuites`, which covers ECDSA as well as RSA certificates for
  TLS 1.2. Why: HARDEN-HTTP-1: both listeners pinned the start-up pair until a restart,
  and the RSA-only suite list failed every TLS 1.2 handshake for an ECDSA certificate.
  Guard: `tls_reload_test.go:TestNewServer_TLS_ECDSAOverTLS12_H2_AndCertReload`,
  `server/tls_reload_ecdsa_test.go:TestStartHTTPServer_TLSReloadsRotatedCertificateAndNegotiatesH2`,
  `internal/tlsreload/tlsreload_test.go`,
  `internal/tlsreload/tlsreload_identity_test.go` (a replacement that keeps the old
  mtime, keeps size and inode, or arrives through a Kubernetes `..data` symlink swap is
  served on the next check, and a cert-first or key-first mismatch window never serves a
  mismatched pair), and
  `internal/tlsreload/reloader_failclosed_fuzz_test.go:FuzzReloaderFailClosed` (fuzzes
  valid/expired/not-yet-valid/mismatched/half-rotated/truncated/empty/deleted/symlink and
  mtime-preserving file-state sequences against a stdlib-loader differential: a cert/key
  mismatch is never served and the previous good pair is always retained on a bad reload).
  A change is detected from the content of both files and the identity of each (size,
  mtime, `os.SameFile`), not from the mtime alone, and the pair that is served is parsed
  from the same bytes that were compared; neither key bytes nor the content digest are
  logged. Not covered: an open gRPC connection keeps its certificate until
  `max_connection_age` recycles it; a file larger than 1 MiB is treated as unreadable and
  the previous pair stays in service; and the check happens at most once per
  `CheckInterval`, so a replacement is served at the first handshake after that interval,
  not immediately.
