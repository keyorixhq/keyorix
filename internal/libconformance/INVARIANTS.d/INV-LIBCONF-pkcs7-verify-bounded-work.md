- **INV-LIBCONF-pkcs7-verify-bounded-work** The four digitorus/pkcs7
  signature-verification entry points (`(*PKCS7).VerifyWithOpts`,
  `(*PKCS7).Verify`, `(*PKCS7).VerifyWithChain`,
  `(*PKCS7).VerifyWithChainAtTime`) must never panic and never hang on ANY
  input that parses successfully via `pkcs7.Parse`.  `VerifyWithOpts`,
  `VerifyWithChain`, and `VerifyWithChainAtTime` carry an additional
  one-directional differential oracle: if any of them ACCEPT against a
  harness-controlled cert pool, then `crypto/x509` chain verification of the
  signer cert against the same pool at the same time must also accept.  This
  catches certificate-chain bypass bugs where pkcs7 accepts something the
  standard library's chain verifier rejects.  `Verify()` uses an empty trust
  store by design and has no differential.  Why: `VerifyWithOpts` is the
  direct production caller in `internal/notary/notary.go:179` on
  attacker-reachable TSA-response bytes; a panic, hang, or chain-bypass in
  the verify path is directly reachable from the notary endpoint.  The oracle
  is intentionally one-directional (ACCEPT ⇒ reference-accepts; it does not
  assert that rejections are correct) because a fuzz-mutated token legitimately
  fails far more often than it succeeds.  Red/green proof: seed token (signed
  by harness leaf) accepted by both VerifyWithOpts and reference (green);
  `fuzzutil.Guard` fires on a hand-crafted infinite-loop in the verify path
  (red — demonstrated against a patched stub before shipping).  Guard:
  `FuzzPKCS7VerifyWithOpts`, `FuzzPKCS7Verify`, `FuzzPKCS7VerifyWithChain`,
  `FuzzPKCS7VerifyWithChainAtTime` (`internal/libconformance`).
