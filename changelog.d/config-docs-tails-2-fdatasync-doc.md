### Documentation
- **fdatasync section completed.** `docs/CONFIGURATION.md` now says the gain scales with how expensive a sync is on the storage in use and that `fsync` stays the default. `internal/storage` pins that the default SQLite DSN carries no `journal_size_limit`, with an in-test case showing the check fails on a DSN that sets one.
