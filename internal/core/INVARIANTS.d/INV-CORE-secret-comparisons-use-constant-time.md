- **INV-CORE-secret-comparisons-use-constant-time** A reviewed subset of
  `internal/core` functions compare secret or bearer-token values and must use
  `subtle.ConstantTimeCompare`, and never `bytes.Equal`, so the comparison
  cannot serve as a timing oracle: (1) `bootstrapSystemLocked`
  (`auth_bootstrap.go`) compares the caller-supplied bootstrap token against
  the server's configured `bootstrapToken` — a variable-time comparison leaks
  partial token matches to an unauthenticated attacker attempting to seize the
  first-admin slot; (2) `validateTOTPStep` (`mfa.go`) compares each TOTP
  candidate code against the expected value — a variable-time comparison
  reduces the brute-force search space for the six-digit validation window;
  (3) `CheckSCIMTokenShape` (`rules/scim_token.go`) compares a newly-configured
  SCIM token against each other currently-configured secret — a variable-time
  comparison lets a caller infer whether a submitted token prefix matches a
  stored secret; (4) `rotateSecret` (`secrets.go`) compares the decrypted
  current secret value against the rotation's new value for no-op detection.
  A `bytes.Equal` call is a violation even next to a `ConstantTimeCompare`
  call (a variable-time early-out beside the constant-time comparison is still
  an oracle); `hmac.Equal` is constant-time and allowed. What this guard does
  NOT cover: string-equality (`==`) comparisons, which a compiler rejects on
  `[]byte` but permits on `string`; a future string-based secret comparison
  would not be caught by the AST check. The list is reviewed, not derived: a
  new secret-comparison site is checked only once it is added to
  `constantTimeComparisonEntries`. The guard is structural (parse-time), not
  statistical. See also the companion invariant in `internal/recoverykey`
  (`Verify` uses `subtle.ConstantTimeCompare` for the same reason: design §6,
  `internal/recoverykey/constant_time_guard_test.go`).
  Guard: `internal/core/guards`
  `TestConstantTimeComparison_UsesConstantTimePrimitive` (each named function
  calls `ConstantTimeCompare` qualified by its `crypto/subtle` import) and
  `TestConstantTimeComparison_NoBytesEqualOnSecret` (no named function calls
  `Equal` qualified by its `bytes` import, aliased and dot-imports included),
  with the checker itself proven red/green on inline fixtures by
  `TestConstantTimeComparison_CheckerFlagsBytesEqual`. Confirmed red when a
  `bytes.Equal` early-out was added beside the bootstrap token's
  `subtle.ConstantTimeCompare`.
