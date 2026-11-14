### Fixed
- **`keyorix-server admin encryption status` now exits non-zero when it cannot read the key state** (#4270). A wrong passphrase, a missing passphrase source, or a live server holding the DEK lock still print the same `❌`/`⚠️` line, but the command then exits 1, like `admin encryption validate`. A preflight such as `encryption status && encryption rotate --confirm` no longer continues past a failed state check. A healthy key set and `Enabled: false` still exit 0.
- **`keyorix-server admin encryption init` now exits non-zero when encryption is disabled in the configuration.** It printed `❌ Encryption is disabled in configuration`, created no keys and exited 0, so a bootstrap script's `encryption init && ...` carried on with no keys. The message is unchanged; `fix-perms` already refused the same way.

### Documentation
- **Key rotation runbook, preflight step 2:** stop the server first, and a failed `admin encryption status` exits non-zero (wrong passphrase, missing passphrase source, held DEK lock).

### Testing
- **New report-only guard `TestNoReturnNilAfterFailureMarker_EncryptionAdmin`** (server/admin, scans server/admin and internal/encryptionops): an exported `*WithConfig` or `run*` function must not `return nil` directly after a `❌` print. Report-only on pull requests until a green nightly on main (docs/guard-rollout.d).
