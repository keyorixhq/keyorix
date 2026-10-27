### Fixed
- **CLI: the right next step after `admin recover-admin`.** A one-time-password session that must change its password (and enrol MFA) now gets "set your own password with `keyorix change-password` ... `keyorix mfa enroll`" instead of the generic "ask a project admin, or request access" hint. `TestEveryAccountSetupCodeHasItsOwnNextStep` reads the server's account-setup codes, so a new one without a hint fails (#3744).
- **CLI help: `user create` and `logout`.** `user create --help` names the hidden prompt and `KEYORIX_INITIAL_PASSWORD[_FILE]` instead of the refused `--password` flag; `logout --help` says what it deletes, including `ca_file` (#3735, #3744).

### Documentation
- **The release-binary golden path.** `docs/demo/GOLDEN-PATH.md` has a ~20-minute demo script from the two release binaries (SQLite or PostgreSQL, TLS and MFA on, upgrade, backup/restore, recovery), walked end to end, and a known-rough-edges list linking #3735-#3744.
- **UPGRADING: v0.96.x -> next.** `audit verify` says `NOT PROVEN` until `audit verify --full` after the first start, and the two deprecated keys v0.96's `admin init` wrote must be deleted before the next minor (#3743). QUICK_START: TOTP codes are single-use, `logout` forgets `ca_file`, and the stale #2941 and example-password lines are gone (#3744).
