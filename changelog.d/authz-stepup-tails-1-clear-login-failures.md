### Fixed
- **Clearing the login-failure counter after a successful step-up or re-authentication can no longer turn into a 500 (#3712).** `clearLoginFailures` already recovered a panic in its storage write; a panic anywhere else in it (the in-memory budget fallback clear) could still reach the caller after the step-up grant committed. It now recovers across its whole body, so `requireReauth`, `VerifyMFAStepUp` and `FinishWebAuthnReauth` no longer need allowlist rows in the best-effort call-site guard. The step-up recovery-code consume itself became panic-safe in #3557.

### Internal
- The best-effort call-site guard's mutation test now deletes `clearLoginFailures`' recover and requires the three MFA callers to be reported; its "unwrap a `besteffort.Run` call site" case moved to `RecordLogin`, because `clearLoginFailures` now protects itself.
