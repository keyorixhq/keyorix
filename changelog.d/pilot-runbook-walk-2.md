### Fixed

- `--new-passphrase-file` (and the other `--new-passphrase-*` flags of `admin encryption rotate-kek` and `migrate-provider`) refusals now name the flag that was given, not `--passphrase-file` (#4217). The refusal itself is unchanged.

### Documentation

- Operator runbooks walked against a native binary (`docs/operator/walk-2026-11-b.md`): break-glass, lost-TOTP, restore failure modes and the startup refusals now match what the product prints, and the product gaps found are recorded.
