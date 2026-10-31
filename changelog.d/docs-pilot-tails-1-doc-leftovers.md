### Documentation
- **Upgrade note 6j corrected: the first recover-admin alert pass resumes from the stored mark.** An install that has used recover-admin before already has a mark at its last alerted id and reads only the audit rows added since; only an install that never used it walks the whole audit table once (`docs/UPGRADING.md`, section 6j).
- **Restore failure modes: after a PostgreSQL restore killed during the load, restore again with `--overwrite-existing`.** `--recover` rolls the data back, but the migrations had already committed, so the database has tables and a new `admin restore` is refused without the flag (`docs/operator/restore-failure-modes.md`).

### Testing
- **The renamed-settings table in `docs/CONFIGURATION.md` is now checked in both directions.** A row for an alias that is no longer in the registry fails `TestConfigurationDoc_AliasTableHasNoStaleRows`, in addition to the existing check that every registry alias has a row.
