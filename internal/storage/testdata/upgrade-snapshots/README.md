# Upgrade snapshots

`<tag>/snapshot.sql` is a SQLite database written by that release's own core
(bootstrap, three users, two projects, seeded-role and group grants, five secrets
with rotations, twelve audit events through the real chain writer), rendered as
SQL with `quote()` so every value round-trips byte-exactly. `manifest.json` records
what the old binary wrote and decided: the secret plaintexts, its own `Authorize`
verdict for every user × permission × scope of the base state, and the number of
seeds and probes on which `ugModel` agreed with that release's real `Authorize`.

Consumed by `FuzzUpgradeFromOldSchema` and `FuzzUpgradeInterrupted`
(`../../upgrade_old_schema_fuzz_test.go`); `ugApplyState` adds generated rows on
top of the replayed old schema, cloning real rows so columns this harness has
never heard of keep the old release's values.

The snapshots carry no key material. They were written under the test key already
committed for `FuzzUpgradeMigration`,
`internal/core/testdata/upgrade-fixtures/v095/{dek.key,kek.salt}`, passphrase in
the manifest. Regenerating a snapshot must keep that key.

## Sources

| tag | notes |
|---|---|
| v0.91.0 | pre-epoch and pre-#1642; audit chain is the pre-#1452 encoding, so only the row count is checked; included in `FuzzUpgradeInterrupted` (its interruption runs the real locked boot path) |
| v0.92.1 | oldest source on HEAD's chain encoding |
| v0.93.0, v0.94.0, v0.95.3, v0.96.3 | releases inside the documented upgrade range |

## Regenerating

The generator is output-only and not committed. For each tag: check the tag out in
a scratch worktree, copy `upgrade_snapshot_state_test.go` into its `internal/core`
with the package clause rewritten, add a test that bootstraps a `KeyorixCore` on a
file database with `Enabled: true` encryption (copy the shared key in first),
creates the base state above through core, runs `ugApplyState` on copies and
compares `core.Authorize` with `ugModel` for every probe, then dumps
`sqlite_master` and every row via `quote()`. Older tags need small signature
adaptations (v0.91.0: no actor argument on grant calls, no `internal/identity`).
