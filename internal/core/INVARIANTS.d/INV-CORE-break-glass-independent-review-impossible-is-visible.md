- **INV-CORE-break-glass-independent-review-impossible-is-visible** When no human other than
  a break-glass activator could ever independently review that activation (a single-admin
  deployment, approximated the same way `guardLastGlobalAdmin*` approximates "another
  administrator exists" -- active global admin-tier holder count), the posture report says so
  explicitly as its own distinct finding
  (`EmergencyAccessPosture.IndependentReviewImpossible`, surfaced as a Gap on a dedicated
  control) rather than silently reading identical to "reviewed" or to an ordinary unreviewed
  backlog. Self-review stays refused regardless
  (INV-CORE-break-glass-review-independent-and-once) — this invariant is about making the
  structural impossibility VISIBLE, not about relaxing who may review. Why: #2461 round 2,
  Andrei's decision item (c). Guard:
  `TestAccumulateBreakGlassPosture_SingleAdminDeploymentFlagsIndependentReviewImpossible`,
  `TestEvaluateControls_EmergencyAccessIndependentReviewerGapsWithOneAdmin`.
<!-- section: Audit (ADR-029) -->
