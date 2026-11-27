### Testing
- **Deterministic timing-invariant guards.** Structural (AST-based) guard tests enforce
  timing-equalization and constant-time comparison invariants in `internal/core` and
  `internal/recoverykey`, replacing reasoning in comments with machine-checked properties.
  `TestTimingEqualization_*` (guards package) checks that every early return before the real
  password comparison in `VerifyPasswordCredentials` and `verifyCurrentPassword` spends the
  dummy bcrypt comparison first, and counts `recordFailedLogin` calls in `VerifyMFACredentials`
  and `requireReauth`. `TestConstantTimeComparison_*` (guards package) verifies that
  `bootstrapSystemLocked`, `validateTOTPStep`, `CheckSCIMTokenShape` and `rotateSecret` call
  `subtle.ConstantTimeCompare` and never `bytes.Equal` (even beside it), with the checker
  proven on inline fixtures. `TestVerify_UsesConstantTimeCompare` and
  `TestVerify_DoesNotUseBytesEqual` (recoverykey package) guard the same property for
  `recoverykey.Verify`. The property tests were confirmed red on targeted mutations.
  Companion INVARIANTS.d fragments added for `internal/core`.
