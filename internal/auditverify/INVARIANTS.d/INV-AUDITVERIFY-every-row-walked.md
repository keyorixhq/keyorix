- **INV-AUDITVERIFY-every-row-walked** Every `audit_events` row with an id up to the last
  one the walk visited, or with a NULL id, must have been visited by the walk; otherwise the
  verdict is BROKEN. The keyset walk (`id > ?`) never visits id 0, a NULL id, or a second row
  under an id a batch ended on (a schema edited to drop the primary key), and such a row
  would otherwise sit in the table unverified, with a verdict that depends on `BatchSize`.
  Why: REVIEW-AUDITVERIFY-KEYFILES-1. Guard: `TestReviewAV_RowsOutsideTheWalkAreBroken`,
  `TestReviewAV_Postgres_IDZeroRowIsBroken` (review_adversarial_test.go).
  The online `VerifyAuditChain` (internal/storage/store) makes the same check since #3808
  (INV-STORE-audit-walk-every-row), and the guard tests assert both verifiers agree.
