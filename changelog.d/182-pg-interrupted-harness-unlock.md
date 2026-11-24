### Testing

- `FuzzUpgradePGInterrupted`: a stop now counts as an interruption only when the migration returned an error. The injected failure on the deferred `pg_advisory_unlock` is swallowed, so that run is a completed upgrade, not a crash; invariant 6 no longer flags it (#182).
