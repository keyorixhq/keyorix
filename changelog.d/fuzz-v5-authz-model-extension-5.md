### Testing

- **Authzdiff V5EXT5: bind mfa.activate, mfa.disable, mfa.recovery-codes.regenerate to the authorization differential.** Adds a `pkMFAEnrollee` fixture principal with a pending enrollment, a `pendingMFARequired` model field for `ActivateMFA`'s enrollment check, and three new op bindings. `mfa.enroll` (BeginMFAEnrollment) is covered structurally by `TestMFARouteGatesPresent`, which asserts `BlockWhenImpersonating` on all four MFA self-service routes. No production-code changes.
