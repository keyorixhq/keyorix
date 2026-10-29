- **INV-AUDITVERIFY-verify-state-row-checked** After a clean walk, `Verify` reads the
  server's `audit_verification_state` row (AUDIT-VERIFY-STATE-1) with its own decoder and
  MAC check, matching `internal/core/audit_verify_state.go`: a missing row while the chain
  holds a `system.audit_verification_state_initialized` or `_discontinuity` event is BROKEN
  (with or without a key); with a key, a row that does not verify (unless it is the row the
  authenticated pending key transition names and that transition's event is not yet in the
  chain), a row carrying a discontinuity, a row claiming ids past the chain head (read
  after the row), or a row whose certified head (its pin, else its last valid check) is
  missing or carries another hash is BROKEN; a missing head is excused only when the
  authenticated retention anchor's RowID is above it (`auditVerifyStateHeadGone`); a placed
  row without a discontinuity whose audit head is below the newest in-chain
  `_discontinuity` event (an older row put back over it) is BROKEN. Why:
  REVIEW-AUDITVERIFY-KEYFILES-1 (offline said VALID where the server said broken);
  REVIEW-3810-DEEP-1 (tail cut and regrown past the claimed head, or rows below it
  re-chained); REVIEW-3810-DEEP-2 (older row put back over a recorded discontinuity). Guard:
  `TestReviewAV_VerifyStateRow_*` (review_adversarial_test.go,
  differential against `core.AuditVerificationStatus`),
  `TestCheckVerifyStateHead_RetentionAnchorBoundary`. **Not covered** (core's rules not
  reimplemented): a failure event above a placed row's audit head that the row does not carry
  ("saved before a break" for failures), the seal-count rule, the unplaced-row rule, and the
  replay rules (generation, checkpoint binding).
