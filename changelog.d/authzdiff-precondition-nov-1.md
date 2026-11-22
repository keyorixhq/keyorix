### Changed
- **The authorization differential tells an unmet precondition from a denial (#4525).**
  `mfa.activate`, `mfa.disable` and `mfa.recovery-codes.regenerate` have no RBAC gate and
  answer HTTP 400 when the caller's account state does not allow them ("no pending MFA
  enrolment", "MFA is not enabled"). The reference model and the REST outcome mapping now
  have a `PreconditionFailed` outcome for exactly that, so the 18 sweep cases that waiver
  known-12 absorbed agree without a waiver, and a handler that answers 200 or 403 for an
  unmet precondition fails the strict sweep. Test-side only: no handler and no status code
  changed. Waiver known-12 and its expiry row are removed.
