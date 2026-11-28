### Security
- **A setup link is handed out only with its audit record.** `IssueSetupToken` and the invitation-with-link path write `setup_token.issued` in the mint's own transaction; if the audit log refuses it, no token is returned or delivered (a self-service reset sends no mail), the subject's previous link stays live, and the caller gets the "could not record the change in the audit log" error.
- **A dynamic credential over a weak admin DSN transport is issued only with its audit record.** When `dynamic_lease.insecure_transport` cannot be written, the issue is refused before anything is minted on the target.
- **A password change or reset never leaves another session live.** `ChangePassword` and the setup/reset-link consume delete the account's other sessions in the same transaction as the new password. If that fails, the change is refused and the old password stays valid (the reset link stays usable). Before, the purge ran after the commit and a failure was only logged.

### Testing
- **Atomicity guard:** the audit-before-write check no longer counts `writeAuditEventFailedFull` (Success=false) events as success claims. A new test fails on a `docs/atomicity-exempt.tsv` row that no longer matches any code (report-only for the first day), and the 12 stale rows it found are removed with their review sidecars.
