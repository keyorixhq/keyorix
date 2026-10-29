### Security
- **`verify-audit` now checks the server's verification state row.** A database-write actor who cut the audit tail and erased the checkpoint rows and the high-water mark (with or without the `audit_verification_state` row) got VALID from `verify-audit --checkpoint-key-file` while the server reported a sticky discontinuity. Offline verification now applies the server's deleted / garbled / past-the-head / recorded-discontinuity rules; a pending key transition's row is accepted as the server accepts it.
- **`verify-audit` verifies every row in `audit_events`.** A row with id 0, or (with a hand-edited schema) a NULL or duplicated id, was never visited by the walk and sat unverified; it is now BROKEN.
- **`verify-audit --db` opens exactly the file named, read-only.** A path containing `?`, `#` or `%` opened a different file, read-write.
- **Key-set manifest writes can no longer tear each other.** Each write stages under its own name, so writers racing past a broken key lock cannot rename a mix of both into place.

### Fixed
- `verify-audit --previous-checkpoint-key-file` now also authenticates an `--anchor` exported before rotate-kek / migrate-provider.
- `verify-audit` no longer reports deleted checkpoints as "never written", and states in "what this run does not prove" when no signed checkpoint was found.
