- **INV-CORE-bulk-suspend-audited-before-effect** A project-wide suspend records ONE
  `secret.bulk_suspend_attempted` event, with the per-suspension `clear_synced_copies` choice and the
  number of secrets it targets, BEFORE it suspends any secret (it is written for a plain bulk suspend too, but only the clear-synced-copies request is fail-closed); when the request carries the
  clear-synced-copies choice and that event is not persisted, it suspends nothing and returns
  `ErrBulkSuspendAuditUnavailable`. Each affected secret then gets the marker through
  `SuspendSecretWithOptions` (the single code path), never by writing the column directly, so the bulk
  and single paths cannot diverge. Why: a decision to empty copies in other clusters must be on record
  first. Guard: `internal/core/project_suspend_clear_copies_test.go`
  (`TestSuspendProjectSecrets_ClearSyncedCopies`: audit-before-effect ordering, fail-closed, marker per
  secret, resume clears it, a caller without write authority marks nothing).
