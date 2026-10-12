### Added
- **Experimental: local append-only audit journal (ADR-115 prototype), off by
  default.** With `local_audit_journal.enabled: true` (plus the required
  `directory` and `replica_id`), audit writes become durable on a local
  group-fsynced journal before a secret is disclosed, and a background
  replicator copies them into `audit_events` with the unchanged ADR-029 hash
  chain. Exactly once: the replay cursor commits with the rows and is
  re-read in each replay transaction, and journal origin is recorded in the
  new `audit_journal_origins` table. A corrupt or truncated journal stops the
  server from starting. The setting is reported as a weakening (start-up
  warning, posture report) and cannot be combined with
  `insecure_audit_skip_durable_sync`. PERF-4 measured it slower than the
  default group commit, so this is for evaluation only. With the setting
  off, the audit write path is unchanged; the migration only adds two empty
  tables (`audit_journal_replay_state`, `audit_journal_origins`).
