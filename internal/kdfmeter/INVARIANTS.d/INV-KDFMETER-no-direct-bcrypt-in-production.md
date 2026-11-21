- **INV-KDFMETER-no-direct-bcrypt-in-production** Production code reaches bcrypt only
  through `internal/kdfmeter`, so the KDF-count oracle sees every password-hash
  operation. The only non-`_test.go` files that import `golang.org/x/crypto/bcrypt`
  directly are the seam itself, the timing-equaliser sentinel builder
  `internal/core/bcrypt_cost.go`, and the manual `scripts/timing-constant-time` tool,
  each listed with its reason. Guard: `TestBcryptImportedOnlyThroughKDFMeter` reads
  import declarations (an aliased import cannot hide, a comment cannot trip it), fails
  on any file outside the allowlist, and fails if an allowlist entry stops importing
  bcrypt; `TestBcryptImportGuard_Calibration` shows it red and green on synthetic
  sources. Does not cover another KDF (scrypt, argon2) or a metered call made the wrong
  number of times per operation.
