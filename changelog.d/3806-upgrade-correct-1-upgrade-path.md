### Fixed
- **SQLite upgrades: hand-written timestamp columns get a type the driver can read back
  (#3440).** The ten `ALTER TABLE ... ADD COLUMN ... TIMESTAMP WITH TIME ZONE` statements
  (users, sessions, secret_nodes) and the user_roles/group_roles primary-key rebuild now
  declare `DATETIME` on SQLite (PostgreSQL DDL is unchanged). None of them runs on a
  database from a supported upgrade source: v0.93.0, v0.94.0 and v0.95.0 databases already
  have these columns. A database from before v0.93 that still reached them got a column
  whose values failed to load ("unsupported Scan ... into type *time.Time"). Guarded by
  `TestNoHandWrittenTimestampColumnDDL`.

### Testing
- **No released binary starts on a database this release migrated (#3359, #3362).** A test
  replays the start-up checks of v0.93 to v0.95.x and v0.96.x against a fresh database, the
  v0.95.0 upgrade fixture and a database v0.96.x left behind. All of those binaries predate
  the v2 audit retention anchor and the suspend clear-copies marker.

### Documentation
- **Rolling upgrade from v0.96.x: don't suspend with "also clear synced Kubernetes copies"
  until the rollout has finished.** A v0.96.x replica ignores the option. See UPGRADING §6q,
  which now also names the refusal v0.93 to v0.95.x binaries print. The schema-epoch refusal
  transcripts in `docs/operator/startup-refusals.md` were re-captured at schema epoch 9, with
  a real v0.96.3 rollback added.
