- **INV-AUTHZDIFF-v5ext8-impersonation-mfa-reset-gates** The
  `impersonation.start` and `mfaReset.cancel` ops are calibrated (admin
  positive control returns Allowed on every participating layer) and their
  route gates are red-proved via planted defects:
  - `impersonation-start-rest-gate-removed` (plants_test.go) removes
    `RequirePermission("users.impersonate")` from the impersonation POST route.
    Non-admin principals then pass the route and reach `requireEqualOrGreaterAdminAuthority`,
    which fails (fixture target holds project_viewer@A and @B; actors lack @B
    coverage) → HTTP 500 → REST=Other, model=Denied →
    `"mapping-gap:other-where-model-denies:REST"` → "unexplained". A strict
    sweep without the plant records zero "unexplained" cases.
  - `mfareset-cancel-core-gate-removed` (plants_test.go) removes the
    `isGlobalAdminRoleName` admin-role check from `CancelMFAReset`. The curated
    variation `{pkCustom, users.write@global, Scope:"global"}` then passes both
    route (users.write@global) and core (gate removed) → REST=Allowed, model=Denied
    (no globalAdminRole) → "O2:allowed-but-model-denies:REST" → "unexplained".
    A strict sweep without the plant records zero "unexplained" cases for this
    variation.
  HARDENING-V5EXT8-1: the route gate for mfaReset.cancel (`users.write@global`)
  is weaker than core's effective gate (`isGlobalAdminRoleName`). The route is
  defense-in-depth; core provides the accurate check. Documented as TODO-ISSUE.
  What these guards do NOT enforce: session-auth check on impersonation.start
  (harness actorCtx defaults sessionAuth to true for all principals); TOTP
  second-factor on RequestMFAReset/ApproveMFAReset (deferred).
  Guard: `TestV5ext8StrictSweep` (default go test, skipped under -short);
  `TestPlantsAreDetected` (CI job authzdiff-plants, opt-in AUTHZDIFF_PLANTS=1);
  `TestImpersonateStartRouterGatePresent`; `TestMFAResetCancelRouterGatePresent`.
