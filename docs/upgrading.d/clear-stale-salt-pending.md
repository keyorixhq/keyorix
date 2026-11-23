## A stale kek.salt.pending is removed with `admin encryption clear-stale-salt-pending`

Before: a `kek.salt.pending` that an interrupted `rotate-kek` left (and a successful server start
proved unused) refused every `admin backup` until it was moved out of the key directory by hand,
and the refusal left no audit record.

Now:

- `keyorix-server admin encryption clear-stale-salt-pending` (server stopped; `--dry-run` first)
  removes it, only when no `dek.key.pending` is present, no `rotate-kek` is running and the active
  key set opens with the current master passphrase without it. It records the removal as an
  `admin.encryption.clear_stale_salt_pending` audit event and refuses in every other case. The
  refusal text, the boot WARN line, `admin validate --posture` and `security.backup_refused`'s
  remedy name it instead of the manual move. A `dek.key.pending` is still never removed.
- A backup refused for a staging file is an `admin.backup_refused` audit event (`success=false`)
  when the database can be opened without changing anything: with the server stopped on SQLite,
  and only when the database is already at this binary's schema epoch. Otherwise the backup's
  stderr says it was not recorded; the refusal itself (exit 4) is unchanged.
- Because the refusal is now an audit event, an archive taken before a refused backup restores on
  the same host only with `--allow-rollback`, as after any audited admin action.

Nothing to do on upgrade. A wrapper that moved `kek.salt.pending` aside by hand keeps working;
switch it to the command to get the checks and the audit record.
