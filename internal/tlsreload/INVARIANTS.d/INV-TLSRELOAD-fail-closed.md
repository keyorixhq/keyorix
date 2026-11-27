- **INV-TLSRELOAD-fail-closed** `Reloader.GetCertificate` never serves a cert/key pair
  that does not load with `tls.X509KeyPair` from the same snapshot: a half-written
  rotation (new cert, old key or vice versa), a truncated file, a deleted file, or any
  other state that causes `tls.X509KeyPair` to fail results in the PREVIOUS valid pair
  being served, never an empty or mismatched one. This is the package's core security
  property: "if it does not load ... the previous pair keeps being served" (package doc).
  Guard: `internal/tlsreload` `FuzzReloaderFailClosed` (sequential differential oracle,
  oracles A/B/C; `reloader_failclosed_fuzz_test.go`; also
  `TestReloader_BrokenRotationKeepsServingPrevious`,
  `TestReloader_MismatchedReplacementWithPreservedMtimeIsNotServed`).
  **Not covered**: permission-denied reads on the host this test suite runs on (root
  bypasses mode bits; explicitly omitted — see test doc comment).
