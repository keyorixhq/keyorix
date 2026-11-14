### Testing
- **Reusable differential-fuzzing kit (`fuzzkit/diffkit`) plus its first instances.** A
  stdlib-only kit compares two or more independent implementations of one security
  decision (accept/reject plus the value extracted on accept) and reports any
  disagreement that a documented-differences table does not explain; a panic or hang in
  one implementation is captured as a verdict, not a crash of the harness. First
  instances in the standalone `fuzzkit/` module: **Instance B** (`fuzzkit/certdiff`,
  `FuzzCertChainDifferential`) differentially fuzzes X.509 chain-trust decisions
  (Go `crypto/x509` vs `openssl verify`) over Frankencert-style chains, and **Instance A**
  (`fuzzkit/jwtdiff`, `FuzzJWTVerifyDifferential`) differentially fuzzes JWT verification
  (`golang-jwt/jwt/v5` vs an independent spec-derived stdlib reference). No production
  code changes.
