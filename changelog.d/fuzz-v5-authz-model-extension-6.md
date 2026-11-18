### Security
- **MFA functions now refuse inactive acting accounts.** `ActivateMFA`, `DisableMFA`, and `RegenerateMFARecoveryCodes` call `requireActorActive` before any password check or business logic, so a suspended account cannot activate, disable, or regenerate MFA credentials. Guarded by `TestSuspendedActorRefusedAtEntryPoints` and `TestCoreRefusesSuspendedActor` (authzdiff matrix row `core_refusal="typed"` for all three).

### Fixed
- **Authzdiff oracle no longer misclassifies HTTP 400 as `Other`.** REST HTTP 400 responses are now mapped to the new `PreconditionFailed` outcome instead of `Other`. The reference model returns `PreconditionFailed` when a principal passes all RBAC checks but lacks the required MFA state (mfa\_activate/mfa\_disable/mfa\_recovery-codes.regenerate). This closed waiver `known-12` (tracking issue #4525) and eliminates the unexplained mapping gap for MFA ops without required MFA state.
