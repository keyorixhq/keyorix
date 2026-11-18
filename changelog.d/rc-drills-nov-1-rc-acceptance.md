### Testing
- **Upgrade drill covers rollback by restore, and prints its time.** `scripts/drills/upgrade.sh` now takes a backup with the old binary before the upgrade and, after the new binary has run on the data, restores it into the old binary (`--overwrite-existing --allow-rollback`; on PostgreSQL the public schema is emptied first, as `docs/operator/upgrade-rollback.md` 4B says). Login, a decrypted secret and `verify-audit` VALID must work again and the post-upgrade write must be gone. Every drill now ends with an `elapsed: Ns (backend: ...)` line before its `PASSED` line.

### Documentation
- **"Verifying a release candidate" block in `docs/operator/upgrade-rollback.md`:** the copy-paste command line for the RC acceptance check (`verify-release.sh`, `check-docs-version.sh` against the final version, the old release's binary checked against its `checksums.txt`, then the SQLite and PostgreSQL upgrade drills).
