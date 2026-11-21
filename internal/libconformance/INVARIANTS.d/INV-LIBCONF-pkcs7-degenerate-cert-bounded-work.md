- **INV-LIBCONF-pkcs7-degenerate-cert-bounded-work** `pkcs7.DegenerateCertificate`
  must never panic and never hang on ANY raw byte input.  The function
  takes arbitrary bytes as a "certificate" (or certificate chain), attempts
  to ASN.1-parse them, and wraps the result in a degenerate PKCS#7
  SignedData container.  bwgen classified it as shape A
  (`func([]byte) (T, error)`) on 2026-11-21; the harness was hand-written
  in `internal/libconformance` rather than committed to
  `internal/boundedworksweep` because the generic bwgen text seeds
  (`"a: 1\n"` etc.) do not trigger meaningful work in `DegenerateCertificate`
  (non-DER input returns immediately at the ASN.1 parse step, leaving both
  the time and allocation measurements below `boundedwork`'s floor
  thresholds — "not judged"), which would cause
  `TestBoundedWorkSweep_EveryTargetJudgesASeed` to fail.  Seeds: real
  DER-encoded certificates from the verify and decrypt harness helpers.
  Why: no fuzz coverage existed for `DegenerateCertificate` prior to LS3;
  it had no test coverage beyond unit tests in the upstream library itself.
  Guard: `FuzzPKCS7DegenerateCertificate` (`internal/libconformance`).
