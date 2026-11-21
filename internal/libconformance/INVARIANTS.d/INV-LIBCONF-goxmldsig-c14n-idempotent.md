- **INV-LIBCONF-goxmldsig-c14n-idempotent** For every canonicaliser `russellhaering/goxmldsig`
  exposes (exclusive C14N 1.0 with/without comments, inclusive C14N 1.0/1.1 with/without
  comments), canonicalisation must be a FIXED POINT: for any parseable XML document,
  `C.Canonicalize(parse(C.Canonicalize(parse(x))))` must equal `C.Canonicalize(parse(x))`. A
  canonical form that is not stable under re-canonicalisation (`b1 != b2`) is a
  C14N-non-idempotence candidate. Why: goxmldsig is the XML-DSig engine under crewjam/saml; on
  every SAML verify it canonicalises the signed element (exclusive C14N) before computing the
  digest, and a signature is only as stable as that canonical form — if re-serialising an
  equivalent spelling (a proxy, a relay, a different prefix) changed the canonical bytes, the
  verification verdict could change. C14N is defined as a normal form precisely to prevent this.
  goxmldsig is otherwise fuzzed nowhere in this repo (only exercised transitively). Scope and
  what the oracle does NOT verify (ancestor-inherited-namespace subtree C14N; the full C14N
  equivalence relation; signature values) are in the target's file header. Guard:
  `FuzzGoxmldsigC14NIdempotent` with its red-proof `TestGoxmldsigC14NIdempotenceRedGreen` and
  budget proof `TestResguardGoxmldsigC14NBudgetRedGreen` (`internal/libconformance`,
  `goxmldsig_c14n_idempotent_fuzz_test.go` + `_redproof_test.go`).
