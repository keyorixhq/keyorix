- **INV-CORE-suspend-clear-copies-lives-with-the-suspension** `SecretNode.SuspendClearSyncedCopies`
  is written only by `SuspendSecretWithOptions` and `ResumeSecret`, through
  `TransitionSecretStatus` (the same conditional write as `Status`, so a racing suspend/resume
  loses loudly and the marker can never outlive or precede its status). Resume always clears it, so
  a later plain suspension never inherits an old choice; a plain suspend of an already-suspended
  secret never downgrades it; suspending again WITH the flag upgrades it. A suspend WITH the flag
  writes its `secret.suspended` audit row (`clear_synced_copies=true`) BEFORE the marker and status
  change; if that row is not persisted it returns `ErrSuspendAuditUnavailable` and writes neither
  (a plain suspend keeps its best-effort audit after the write). Why: SUSPEND-PURGE-1. Guard:
  `secret_suspend_clear_copies_test.go` (`TestSuspendSecret_ClearSyncedCopies`, incl. audit-write failure -> refused, no marker).
