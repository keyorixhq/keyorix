### Fixed
- **Rolling upgrade: an older replica saving the audit verification state no longer leaves
  `audit verify` permanently BROKEN (#3708).** During a Helm `RollingUpdate` (replicas > 1),
  a replica from before the audit verification state was placed against the chain re-signs
  the state without those fields. The new version used to read that as a sticky
  "before a recorded break" discontinuity that no command could clear over an intact chain.
  Now the `system.audit_verification_state_initialized` event names the state generation
  that placed the state, and a row an older replica re-signed after it is restarted instead:
  the status reads `not_proven` (the `KeyorixAuditVerifyStateRejected` alert can fire during
  the rollout) until a full verification passes, which a rolling cycle does on its own, or
  run `keyorix audit verify --full` once every replica runs the new version. A row from
  before the upgrade, a replayed row, a row saved before a recorded break and a re-sign that
  dropped a discontinuity still latch. A deployment whose marker event predates this change
  gets a named one with its next state save; an older replica's save before that still
  latches, so finish that first rollout before rolling back.

### Testing
- **Rolling-upgrade compatibility, with the older binary's exact writes (#3362, #3359, #3708).**
  A PostgreSQL test plays v0.96.3's `TransitionSecretStatus` statement (resume, then a plain
  suspend) between this version's clear-copies suspend and its read, which must not carry
  the clear-copies marker. Audit verify state tests play the row an older replica's save
  writes (the fields its struct knows, the next generation, the current checkpoint trail).
