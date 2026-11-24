### Testing

- `FuzzUpgradePGInterrupted`: a stop that fails only the deferred `pg_advisory_unlock`, whose error production ignores, now counts as a completed upgrade, not a crash; invariant 6 no longer flags it. Any earlier failure a migration swallows and commits is still an interruption, guarded by `TestUpgradePGInterrupted_SwallowedFailureStillFires` (keyorixhq/fuzz-corpus#182).
