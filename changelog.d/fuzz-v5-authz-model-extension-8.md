### Security

- authzdiff: bind `impersonation.start` (StartImpersonation) and `mfaReset.cancel`
  (CancelMFAReset) to the cross-layer authorization differential harness; both are
  backed by planted-defect self-tests (V5EXT8).
- authzdiff: document HARDENING-V5EXT8-1: the route gate for
  `POST /api/v1/mfa-reset-requests/{id}/cancel` uses `users.write@global` but the
  effective check in core is `isGlobalAdminRoleName`; the route gate is weaker than
  the real requirement (TODO-ISSUE).
