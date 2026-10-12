- **INV-CORE-break-glass-review-independent-and-once** A break-glass activation's
  post-activation review is recorded by someone OTHER than the activating user, by an
  attributable human (never `actorID==0`), exactly once, and only after the activation has
  concluded (revoked or expired). Break-glass activation is deliberately single-person
  (ADR-112 rejects two-person break-glass: "an emergency path that needs a second person
  fails exactly when it's needed"), so the independent after-the-fact review is the ONLY
  second pair of eyes in the whole lifecycle — a self-review collapses the property to one
  person end to end. There is no co-approver to also exclude: `BreakGlassActivation` carries
  no approver field, so the reviewer and the activating user are the only two identities an
  activation has. Why: ADR-112 §3, #2461. Guard: `break_glass_review_test.go`
  (`TestReviewBreakGlass_RefusesSelfReview`,
  `TestReviewBreakGlass_RefusesUnattributableReviewer`,
  `TestReviewBreakGlass_RefusesWhileStillActive`,
  `TestReviewBreakGlass_AllowedOnConcludedActivation`), plus
  `TestBreakGlassActivation_HasNoApproverField`, which guards the no-co-approver PREMISE
  rather than the conclusion so adding co-approval later fails loudly instead of silently
  reopening a second self-review path.
<!-- section: Audit (ADR-029) -->
