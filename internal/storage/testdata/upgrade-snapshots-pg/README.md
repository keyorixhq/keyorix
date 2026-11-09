# PostgreSQL upgrade snapshots

**Status: no snapshot has been generated yet.** The lab connection failed before
the first run finished, so the tests that need one skip, and nothing below has been
shown on PostgreSQL. Run the recipe under "Regenerating" for each of v0.91.0 (adapter
`v091`), v0.92.1, v0.93.0, v0.94.0, v0.95.3 and v0.96.3 (adapter `v092plus`).

`<tag>/snapshot.sql` is a PostgreSQL database written by that release's own core
running against PostgreSQL (bootstrap, three users, two projects, seeded-role and
group grants, five secrets with rotations, twelve audit events through the real
chain writer), rendered from the catalogs: sequences, tables, rows, constraints,
indexes, functions, triggers, sequence values. Statements are separated by a marker
line, not parsed. `manifest.json` records the secret plaintexts, that release's own
`Authorize` verdict for every user × permission × scope of the base state, and the
number of seeds and probes on which `ugModel` agreed with that release's real
`Authorize` on PostgreSQL.

Consumed by `FuzzUpgradePGFromOldSchema` and `FuzzUpgradePGInterrupted`
(`../../upgrade_pg_fuzz_test.go`). `pgApplyState` adds generated rows on top of the
replayed old schema, cloning real rows so columns the harness has never heard of
keep the old release's values.

The snapshots carry no key material. They were written under the test key already
committed for `FuzzUpgradeMigration`,
`internal/core/testdata/upgrade-fixtures/v095/{dek.key,kek.salt}`, passphrase in
the manifest. Regenerating a snapshot must keep that key.

## Why regenerated, not translated

The SQLite snapshots are not reused: a translated snapshot would prove what the
translator wrote, not what an old binary wrote. Regeneration means the old
release's own migrations produced the PostgreSQL column types, defaults,
constraints and indexes the upgrade then has to deal with.

What this cannot show: the state of a database that has been upgraded repeatedly
over its life (each snapshot is a fresh install of one release, then used), data
shapes the generator does not write (machine identities, MFA, SSO), and any
difference between the PostgreSQL 16 used here and other server versions.

## Regenerating

`generator/regen.sh <tag> <checkout> <v091|v092plus>`, from the repository root,
with `KEYORIX_TEST_PG_DSN` set and `<checkout>` a throwaway checkout of the tag. It
copies the state files and generator into the checkout's `internal/storage`, and
runs `TestW6GenPGSnapshot` there. That test also rejects the snapshot unless the
replayed copy dumps identically to the source database (the fidelity check) and
`ugModel` matches the release's `Authorize` on a stride of the probes of 8 generated
states (the manifest has the counts; the SQLite leg's 40-seed validation of the same
rule stands beside it, these seeds are for the PostgreSQL path). Databases are
named `w6_gen_*` and dropped.
