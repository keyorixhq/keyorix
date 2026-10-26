### Changed

- Internal refactor, no behaviour change: the federated-JWT verifier (`OIDCVerifier`, `OIDCTrustedIssuer`, `JWKSResolver`, `HTTPJWKSResolver`) moved from `internal/core` to the new leaf package `internal/oidcverify`, and `PATRestriction` and `Scope` moved to `internal/core/rules`; `internal/core` keeps every name as an alias. The fuzz targets `FuzzOIDCVerifierVerify`, `FuzzOIDCVerifierClaims` and `FuzzPATRestrictionAllows` moved with them, so their coverage map shrinks from about 481 KiB to 57 KiB and 35 KiB (ADR-109 Step 7, ADR-121).
