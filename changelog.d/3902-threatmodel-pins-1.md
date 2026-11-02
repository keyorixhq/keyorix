### Documentation
- **Threat-model GAP rows now cite their pinning tests.** In `docs/security/threat-models/`, SHARE-13 (sharing lifecycle: #2794, #2796, #2797, #2798, #2801, #2802, #2887 and the purge half of #2795), RL-5 (#3429), DYN-3/DYN-4 (#3424) and BG-6 (#3420) name the tests on `main` that pin each fix, and the README's GAP index says which issues can close. The read side of #2795 (`GetUserRoleIDsAt` and its siblings still `LEFT JOIN projects`) stays a GAP.

### Testing
- **Renew-side dynamic-secret guards are pinned.** `TestDynamicSecrets_RenewRefusesNoNativeExpiryBackendWithoutSweeper` checks that `RenewLease` refuses a backend without native expiry while the lease sweeper is off, and `TestDynamicSecrets_RenewRevalidatesAdminDSN` checks that renew refuses a stored admin DSN pointing at a private or link-local address once private targets are disallowed, without calling the engine or moving the expiry.
- **Resuming a secret in a soft-deleted project is refused.** `TestResumeSecret_RefusedInDeletedProject` (SQLite) asserts `ErrProjectNotFound` and that the secret stays `suspended`.
