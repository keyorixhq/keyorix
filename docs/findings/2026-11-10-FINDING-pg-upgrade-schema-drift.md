# PostgreSQL upgrade: fresh-install schema objects not backfilled on upgrade

Classification: DEFECT (minor — one performance index), with the general pattern
being the point of interest. Found by the W6 PostgreSQL upgrade-fuzz leg
(oracle 8), 2026-11-10, on a real PostgreSQL 17.11 server.

## What the oracle found

Oracle 7/8 compare an upgraded database (an old release's own schema + the current
tree's migrations) against a fresh install of the current tree. Across the six
generated snapshots, after classifying every difference (see `pgSchemaIgnored` in
`internal/storage/upgrade_pg_fuzz_test.go`), one difference falls inside the
documented v0.93.x+ supported upgrade range and is a real drift:

    indexes idx_break_glass_activations_reviewed_by missing on the upgraded database
      (fresh has: CREATE INDEX ... ON public.break_glass_activations (reviewed_by))

It is missing after upgrading from v0.91.0, v0.92.1, v0.93.0, v0.94.0 and v0.95.3 —
i.e. from every release before v0.96 — and present only when upgrading from v0.96.3.

## Cause

`models.go`'s `BreakGlassActivation.ReviewedBy` carries `gorm:"index"` (added in the
v0.96 line). On a fresh install the AutoMigrate tail creates
`idx_break_glass_activations_reviewed_by` from that tag. There is no explicit
`migrate_*.go` step that creates the index (confirmed by grep: the only occurrences
of the name are the model tag and the fuzz harness). Keyorix runs AutoMigrate only on
a fresh install (the `freshInstallComplete` tail); an existing database is migrated by
the ordered explicit steps alone. So an index (or column) first expressed as a model
tag *after* a release is created on new installs but never backfilled to databases
first installed at an older release.

This is the same mechanism as the SQLite leg's `owner_machine_identity_id` class and
the below-floor machine-identity columns this leg also surfaced for v0.91.0 — a model
object with no explicit backfill migration. Here it is benign: a non-unique btree on a
low-cardinality, low-volume, security-sensitive table (`break_glass_activations`),
so the only effect is a sequential scan where a fresh install would use the index.
No correctness or security consequence; break-glass reviews are rare.

## Why it is only ignored, not fixed here

W6 does not change production code or migrations. The difference is recorded in
`pgSchemaIgnored` with the key `indexes:idx_break_glass_activations_reviewed_by` and a
reason pointing here, so oracle 8 stays calibrated: it still fires on any *other*
constraint/index drift, on any tag, including a new one on this table.

## Recommendation for Andrei

If the index matters, add an explicit idempotent migrate step
(`CREATE INDEX IF NOT EXISTS idx_break_glass_activations_reviewed_by ON
break_glass_activations (reviewed_by)`) so upgraded databases match fresh ones, then
remove the ignore-list entry and let oracle 8 enforce equality. More broadly: a model
field gaining `gorm:"index"` or a new column with no matching explicit migration is
invisible to every already-installed database. A guard that diffs the AutoMigrate
target schema against the sum of the explicit steps would catch this class at the
source (prefer the machine-checked over the asserted). The benign instances found
here (this index; the below-floor machine-identity columns) are the visible edge of
that general gap.

## Reproduce

    KEYORIX_TEST_PG_DSN=... go test ./internal/storage -run \
      '^FuzzUpgradePGFromOldSchema$' -count=1    # green with the ignore-list entry
    # Temporarily delete the "indexes:idx_break_glass_activations_reviewed_by" entry
    # from pgSchemaIgnored to see oracle 8 report it for v0.93.0/v0.94.0/v0.95.3.
