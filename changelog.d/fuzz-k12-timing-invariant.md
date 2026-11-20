### Testing
- **Deterministic timing-invariant guards.** Three new structural (AST-based) guard tests enforce
  timing-equalization and constant-time comparison invariants in `internal/core` and
  `internal/recoverykey`, replacing reasoning in comments with machine-checked properties.
  `TestTimingEqualization_*` (guards package) counts dummy-bcrypt calls in
  `VerifyPasswordCredentials` and `verifyCurrentPassword`, and `recordFailedLogin` calls in
  `VerifyMFACredentials`. `TestConstantTimeComparison_*` (guards package) verifies that
  `bootstrapSystemLocked`, `validateTOTPStep`, and `CheckSCIMTokenShape` use
  `subtle.ConstantTimeCompare` and not `bytes.Equal`. `TestVerify_UsesConstantTimeCompare`
  and `TestVerify_DoesNotUseBytesEqual` (recoverykey package) guard the same property for
  `recoverykey.Verify`. All nine tests confirmed red on targeted mutations and green restored.
  Companion INVARIANTS.d fragments added for `internal/core`.
