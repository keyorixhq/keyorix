### Fixed
- **MFA reset tails (REVIEW-3838-DEEP-1 L1-L3).** Registering a passkey now clears the
  enrolment an administrator MFA reset demanded, in the same transaction as the credential,
  so removing that passkey later no longer confines the user to enrolment again. An MFA
  reset approval refused inside its transaction (the request decided meanwhile, or the
  requester, approver or target changed) now leaves a DENIED `mfa.reset_approved` audit
  row, as the earlier refusals do. An audit-log outage on the MFA reset routes now answers
  like every other audited mutation: 503 with `Retry-After` and error code
  `audit_unavailable` (was `AuditUnavailable`, without `Retry-After`).
