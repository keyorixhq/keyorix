### Fixed
- **MFA reset tails (REVIEW-3838-DEEP-1 L1-L3).** Registering a passkey now clears the
  enrolment an administrator MFA reset demanded, in the same transaction as the credential,
  so removing that passkey later no longer confines the user to enrolment again. An MFA
  reset approval refused because the request expired or was decided, the requester or the
  target changed, or the approver has no second factor now leaves a DENIED
  `mfa.reset_approved` audit row, whether the refusal is decided before or inside the
  approval transaction (before, only some of these refusals were audited). An MFA reset
  request refused because the requester has no second factor now leaves a DENIED
  `mfa.reset_requested` row. An audit-log outage on the MFA reset routes now answers
  like every other audited mutation: 503 with `Retry-After` and error code
  `audit_unavailable` (was `AuditUnavailable`, without `Retry-After`).
