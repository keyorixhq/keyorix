### Fixed
- **Setting a secret's access schedule no longer revives a deleted schedule or drops hour 0.** `SetSecretAccessSchedule` was FirstOrCreate followed by a full-row Save: a schedule deleted by another replica in between came back under its old id, one deleted and re-created in between made the set fail with a unique-constraint error, and moving an existing window's start to hour 0 was silently not written. It is now a column-scoped UPDATE conditional on the row existing, else an INSERT ... ON CONFLICT DO NOTHING.

### Testing
- **DeleteEnvironment / RestoreProject / DeleteProject lock-order check.** A two-environment project is deleted, then both environment deletes, the restore and a re-delete run concurrently on four Postgres pools, 200 times; no call may deadlock or fail outside its documented refusals, and no active secret may end in a deleted environment (#4287 follow-up).
