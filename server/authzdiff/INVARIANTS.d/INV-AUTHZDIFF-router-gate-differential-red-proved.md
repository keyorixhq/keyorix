- **INV-AUTHZDIFF-router-gate-differential-red-proved** An op whose matrix row is
  `core_refusal:"none"` (coreEnforced==false) is a TRANSPORT-ENFORCED (ID-2)
  differential: its core leg is recorded but excluded from both oracles, so Oracle 2
  compares the REST router's scoped/global permission gate against the independent
  model, and the gate it binds must be the router gate the route actually carries —
  never a core permission the core method does not check. The V8 bindings are this
  shape: `access-review.campaign.open` (router `RequireScopedPermission(permRolesAssign,
  projectScope)`; `core.OpenAccessReviewCampaign` does NO authorization — its own
  comment records that opening is deliberately not human-gated so the scheduler can
  auto-open overdue campaigns) and `riskexception.create` (router
  `RequirePermission(permSystemWrite)` at global scope; `core.CreateRiskException`
  enforces only human-only + a bounded sunset + a SoD-live-violation check when
  category=="sod" — the binding uses a non-sod category so only the router gate
  varies by principal). Each is calibrated (admin positive control `Allowed`) and
  red-proved by REMOVING THE ROUTER GATE in a `-overlay` scratch copy (the working
  tree is never edited) and asserting the restricted strict sweep produces at least
  `minUnexplained` `unexplained` cases on that op alone (a present transport allowing
  what the model denies — the one direction no waiver absorbs), with the same sweep
  WITHOUT the overlay producing zero. Why: a transport-only gate is exactly the
  `router-gate-removed` plant shape already trusted for `group.delete`; "a guard
  nobody has watched fail is not a guard" and "when a verdict depends on a condition,
  guard the condition, not the conclusion" (root `CLAUDE.md`) — the condition here is
  the router gate, so the oracle and its red proof both target the router gate, not
  the core method that does not enforce it.
  Guard: `TestV8StrictSweep` (default `go test`, skipped under `-short`) runs the
  deterministic strict sweep over the V8 bindings and fails on any uncalibrated or
  `unexplained` case; `TestEveryV8OpHasNoGRPCLeg` guards its no-gRPC fast path;
  `TestPlantsAreDetected` (CI job `authzdiff-plants`, opt-in `AUTHZDIFF_PLANTS=1`) runs
  the `access-review-campaign-open-router-gate-removed` and
  `riskexception-create-router-gate-removed` plants; the `uncalibrated`/`unexplained`
  failure paths of `TestAuthzDiffSweep`/`FuzzAuthzDiff`. Does NOT verify the core-leg
  business rules these endpoints also run (campaign lifecycle, reviewer independence /
  human-reviewer / grant-exists on attest/revoke/decide, dual-control and
  SoD-live-violation on risk-exception approve, the creator-or-admin rule on delete);
  those are excluded with the core leg (ID-2) and left analyzed-not-bound — see the
  V8 report.
