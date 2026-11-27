### Testing
- **FuzzReloaderConcurrentLoad**: add a concurrent fuzz target for `internal/tlsreload`
  that drives the Reloader through fuzz-chosen cert/key file mutations while N=4 goroutines
  call `GetCertificate` concurrently (two direct, two via real TLS handshakes against an
  in-process loopback listener). Oracles: no empty/partial cert (A), no cert/key mismatch
  ever served (B), only coherently-written pool pairs ever served (C/fail-closed), no data
  race under -race (D), no goroutine leak (E). Fills the gap noted in
  `FuzzReloaderFailClosed`'s doc comment: "does not cover concurrent GetCertificate callers."
  Adds `INV-TLSRELOAD-concurrent-load-lock` to the package's invariant inventory.
