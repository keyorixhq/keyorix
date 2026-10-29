- **INV-AUDITVERIFY-verify-state-row-checked** After a clean walk, `Verify` reads the
  server's `audit_verification_state` row (AUDIT-VERIFY-STATE-1) with its own decoder and
  MAC check, matching `internal/core/audit_verify_state.go`: a missing row while the chain
  holds a `system.audit_verification_state_initialized` or `_discontinuity` event is BROKEN
  (with or without a key); with a key, a row that does not verify (unless it is the row the
  authenticated pending key transition names and that transition's event is not yet in the
  chain), a row carrying a discontinuity, or a row claiming ids past the chain head (read
  after the row) is BROKEN. Why: REVIEW-AUDITVERIFY-KEYFILES-1 (offline said VALID where the
  server said broken). Guard: `TestReviewAV_VerifyStateRow_*` (review_adversarial_test.go,
  differential against `core.AuditVerificationStatus`). **Not covered**: the row's pin,
  failure, seal-count and unplaced-row rules.
