# ADR-097: Schema-epoch startup guard against silent downgrade

## Status

**Accepted (2026-09-02).** Follow-up to the 2026-09 security review
(`docs/security-review-2026-09.md`), which named migration downgrade safety
as explicitly out of scope. This ADR closes that gap.

## Summary

`migrateDatabase` (`internal/storage/factory.go`) is a single, monotonic,
always-forward migration function: GORM `AutoMigrate` plus a long sequence of
idempotent `ALTER TABLE ... ADD COLUMN` statements, each gated on
`columnExists`/`tableExists`. It has no notion of schema version, and nothing
anywhere in the boot path checks whether the database it's about to run
against was already migrated by a *newer* binary than the one currently
starting. If an operator rolls back to an older release while pointing at
the same database — a plausible operational action during a bad deploy, not
a hypothetical — the older binary boots and runs normally against a schema
it doesn't fully understand.

Investigating this directly (tracing `roles.bypasses_permission_checks`,
`user_roles.environment_id`/`group_roles.environment_id`, and
`secret_nodes.classification` and its siblings through their actual
authorization call sites — `GetUserRoleIDsAt`'s scope filter in
`internal/storage/store/local_rbac.go`, `classification_gate.go`'s gate
check, `verifyBatchEvents`'s audit-hash-chain walk) found that every
column added by `migrateDatabase` to date happens to default in the safe
direction: an old binary's `INSERT` that doesn't know a column exists gets
that column's DB-level `DEFAULT`, and in every case checked, that default
reproduces the pre-migration semantics rather than widening them
(`bypasses_permission_checks DEFAULT false` = no bypass;
`environment_id DEFAULT 0` = the old, pre-environment-scoping "applies to
the whole project" behavior, not a wildcard grant; `classification DEFAULT
''` = unclassified, the same no-extra-gate state a pre-classification
binary always produced; an empty audit `entry_hash` appearing after the
chain has started is already caught by `verifyBatchEvents`'s "missing entry
hash on a chained event" check, not silently tolerated).

That is a real, verified-safe result — but it holds only because every
migration author so far independently made the correct default-direction
choice. Nothing enforces that this stays true for the next one. A future
migration that adds, say, a `require_step_up BOOLEAN NOT NULL DEFAULT
false` where `false` is the *permissive* direction would reproduce exactly
the silent-regression shape this review looked for and didn't find —
individually undetectable without re-doing this same trace for every future
column, by hand, forever.

**Decision: add a structural startup guard, not a documentation convention.**
This matches the review's own stated taste (`docs/security-review-2026-09.md`:
"the raw-storage-bypass class is closed by a guard, not by a fixed list";
"the 404-vs-403 finding produced a house convention... not a single patch")
— close the *class* of problem (an old binary silently running against
unknown schema) rather than re-auditing each instance of it.

## The mechanism

A monotonically increasing integer, `currentSchemaEpoch`, compiled into the
binary next to `migrateDatabase` itself. Every PR that changes
`migrateDatabase` in a way that adds or alters schema must bump it by one —
a single `const` at the top of `factory.go`, impossible to miss when editing
the function directly below it.

- **Write**: after `migrateDatabase` completes successfully — not before,
  and not on partial/failed completion — it upserts `currentSchemaEpoch`
  into `system_metadata` under the key `schema_epoch`, using the same
  `system_metadata` table and upsert idiom `SetSystemMetadata` already uses
  (`internal/storage/store/local_system_metadata.go`), but written directly
  against the `*gorm.DB` handle `migrateDatabase` already holds — the
  `storage.Storage` wrapper doesn't exist yet at this point in
  `createLocalStorage`/`createPostgresStorage`.
- **Check**: as the very first thing `migrateDatabase` does, before any
  `ALTER TABLE`/`AutoMigrate` call. If `system_metadata` doesn't exist yet,
  this is a fresh install (or a database from before `system_metadata`
  itself existed, i.e. pre-ADR-029 — in practice indistinguishable from
  fresh at this point) — proceed unconditionally, nothing to compare
  against. If the table exists but the `schema_epoch` key was never written
  (an older binary that predates this guard), proceed unconditionally too —
  absence of a recorded epoch cannot itself justify refusing to start. If
  the key exists and parses to a value **greater than** `currentSchemaEpoch`,
  refuse: return an error before any migration step runs, with a message
  naming both epochs and telling the operator this binary is older than the
  database it's pointed at.
- **Corrupt value**: if the key exists but doesn't parse as an integer,
  fail closed (refuse to start) rather than silently proceeding — matching
  `migrateDatabase`'s existing `#G54` fail-closed discipline for a failed
  `ALTER` (a silently-skipped check is worse than a loud one an operator
  has to clear manually).

## What this does not solve

- **The legacy `migrations/*.down.sql` files** (`migrations/README.md`)
  remain what they always were: unused by any code path in this repo,
  runnable only via a manually-invoked external `golang-migrate` binary.
  This guard has no interaction with them and doesn't make them any more or
  less safe than before.
- **It doesn't replace tracing a new migration's default-direction safety.**
  A migration author still has to reason about which direction is safe for
  a new column — this guard only stops an *old* binary from running against
  a schema that already has an unsafe-if-ignored column; it says nothing
  about whether a *new* binary's own migration chose the right default in
  the first place. That reasoning is still a human judgment call at
  migration-authoring time, the same as it always was.
- **No automated check enforces bumping `currentSchemaEpoch`.** A test that
  tries to infer "did this diff change something that requires an epoch
  bump" would have to distinguish semantically-relevant schema changes from
  comment/refactor-only changes inside a 250+ cyclomatic-complexity
  function — not reliably automatable. This is a convention backed by
  proximity (the constant sits directly above the function) and this ADR,
  not a machine-checked gate. Stated here as a known limitation, not an
  implied "and therefore machine-enforced."
- **This is not a replacement for testing an actual downgrade.** The guard
  makes a downgrade fail loudly instead of silently; it doesn't test that
  every application code path behaves correctly on the *older* binary's own
  side once it refuses (i.e., that refusing to start is itself clean —
  which the test suite added alongside this ADR does cover for the
  `migrateDatabase`/`createLocalStorage`/`createPostgresStorage` boundary,
  but not for process-manager or orchestrator-level restart-loop behavior).

## Alternatives considered

- **Warn-and-continue instead of refuse-to-start.** Rejected: the whole
  point is that the failure mode this guards against is silent. A warning
  that isn't tied to actual startup failure will be missed in exactly the
  incident-response scenario (a bad deploy, someone rolling back fast) where
  it matters most.
- **A full versioned migration framework (numbered up/down files, a
  `schema_migrations` table tracking every individual step).** Rejected as
  disproportionate: `migrateDatabase`'s existing idempotent-additive design
  already handles forward migration correctly and has for a long time; the
  actual gap this ADR closes is narrow (no downgrade detection), and a full
  reframe of the migration system is a much larger, riskier change than the
  problem warrants.
- **Per-column safety documentation instead of a version gate.** Rejected
  per the "guard, not a fixed list" reasoning above — a checklist a future
  PR author has to remember to consult doesn't survive the same way a
  compile-time-adjacent constant and a startup check does.
