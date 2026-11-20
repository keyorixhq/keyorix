- **INV-CORE-secret-comparisons-use-constant-time** Three functions in
  `internal/core` compare secret or bearer-token values and must use
  `subtle.ConstantTimeCompare` so the comparison cannot serve as a timing
  oracle: (1) `bootstrapSystemLocked` (`auth_bootstrap.go`) compares the
  caller-supplied bootstrap token against the server's configured
  `bootstrapToken` — a variable-time comparison leaks partial token matches
  to an unauthenticated attacker attempting to seize the first-admin slot;
  (2) `validateTOTPStep` (`mfa.go`) compares each TOTP candidate code against
  the expected value — a variable-time comparison reduces the brute-force
  search space for the six-digit validation window; (3) `CheckSCIMTokenShape`
  (`rules/scim_token.go`) compares a newly-configured SCIM token against each
  other currently-configured secret — a variable-time comparison lets a caller
  infer whether a submitted token prefix matches a stored secret. What this
  guard does NOT cover: string-equality (`==`) comparisons, which a compiler
  rejects on `[]byte` but permits on `string`; a future string-based secret
  comparison would not be caught by the AST check. The guard is structural
  (parse-time), not statistical. See also the companion invariant in
  `internal/recoverykey` (`Verify` uses `subtle.ConstantTimeCompare` for the
  same reason: design §6, `internal/recoverykey/constant_time_guard_test.go`).
  Guard: `internal/core/guards`
  `TestConstantTimeComparison_UsesConstantTimePrimitive` (each named function
  calls `ConstantTimeCompare` in its body) and
  `TestConstantTimeComparison_NoBytesEqualOnSecret` (no named function uses
  `bytes.Equal` as a replacement). Both confirmed red when the respective
  `subtle.ConstantTimeCompare` call was replaced with `bytes.Equal` and green
  when restored.
