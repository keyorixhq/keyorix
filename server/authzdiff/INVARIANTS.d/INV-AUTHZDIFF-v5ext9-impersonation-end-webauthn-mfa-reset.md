- **INV-AUTHZDIFF-v5ext9-impersonation-end-webauthn-mfa-reset** The
  `impersonation.end`, `webauthn.deleteCredential`, `mfaReset.request`, and
  `mfaReset.approve` ops are calibrated (controlAs positive controls return
  Allowed on every participating layer) and two ops are red-proved via planted
  defects:
  - `impersonation-end-session-check-removed` (plants_test.go) patches
    `EndImpersonation` to skip the `session.ImpersonatedBy == nil` check.
    Without it, any authenticated user's regular session is consumed by
    `DeleteSession` and the handler returns 200 → REST=Allowed, model=Denied
    (no impersonating session) → "O2:allowed-but-model-denies:REST" →
    "unexplained". A strict sweep without the plant records zero "unexplained"
    cases.
  - `webauthn-delete-credential-error-swallowed` (plants_test.go) patches
    `DeleteWebAuthnCredential` in the handler to swallow the `requireReauth`
    error. Principals without MFA then get 200 instead of 400 →
    REST=Allowed, model=Denied/PreconditionFailed → O2:allowed-but-model-*
    → "unexplained". A strict sweep without the plant records zero cases.
  HARDENING-V5EXT9-1: the route gate for `mfaReset.request` and
  `mfaReset.approve` (`users.write@global`) is weaker than core's effective
  gate (`requireMFAResetActor`: globalAdminRole + TOTP second factor). Same
  pattern as HARDENING-V5EXT8-1. No plant added for this HARDENING: the TOTP
  second-factor requirement makes a curated-variation plant impractical without
  an additional TOTP fixture user. Documented as TODO-ISSUE.
  What these guards do NOT enforce: WebAuthn passkey assertion path
  (BeginWebAuthnReauth/FinishWebAuthnReauth — requires webauthnRP, nil in
  this harness; deferred); BeginWebAuthnRegistration / ListWebAuthnCredentials
  (deferred); mfaReset dual-control requester-change guard; requireReauth
  anti-replay (not modelled).
  Guard: `TestV5ext9StrictSweep` (default go test, skipped under -short);
  `TestPlantsAreDetected` (CI job authzdiff-plants, opt-in AUTHZDIFF_PLANTS=1);
  `TestEndImpersonationRouterGatePresent`; `TestDeleteWebAuthnCredentialRouterGatePresent`;
  `TestMFAResetRequestRouterGatePresent`; `TestMFAResetApproveRouterGatePresent`.
