- **INV-CORE-break-glass-unreviewed-reported-never-blocks-activation** An activation
  unreviewed past `break_glass.review_window` is REPORTED (posture report count + age, the
  "emergency-access" control going to Gap — not merely informational -- a recurring
  `SECURITY:` log line, a repeating admin notification, and one `break_glass.review_overdue`
  audit event per pass) and a pending review never ENFORCES a lockout on break-glass
  ACTIVATION itself. ADR-112's words are "an open activation without a recorded review shows
  as a posture deviation" — visibility, escalating until acted on, is the control for the
  activation path specifically, by the same reasoning that rejected two-person break-glass.
  This narrowly scopes to activation only (#2461 round 2, Andrei's decision): it does NOT
  forbid a future, separately-decided, opt-in enforcement elsewhere (e.g. a policy freezing
  risky admin config changes until a pending review clears) — only "a pending review blocks
  activation" is ruled out without a fresh product decision. A still-active unreviewed
  activation is counted too ("an OPEN activation"), which matters because
  INV-CORE-break-glass-review-independent-and-once refuses to review one that is still
  active — excluding them would hide exactly the activations that cannot be closed out yet.
  Why: ADR-112 §3 items 4–5, #2461. Guard:
  `break_glass_review_surfacing_test.go:TestAccumulateBreakGlassPosture_CountsUnreviewedPastTheWindow`,
  `TestEvaluateControls_EmergencyAccessGapsOnUnreviewedActivation`,
  `TestRunBreakGlassReviewReminder_WarnsAndAuditsOncePerPass`,
  `TestRunBreakGlassReviewReminder_NotifiesAdmins`,
  `TestRunBreakGlassReviewReminder_StorageErrorIsReported` (a broken query must not read as
  "nothing is overdue"), `TestBreakGlassReviewWindowDefaultMatchesConfig`.
<!-- section: Audit (ADR-029) -->
