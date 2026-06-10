# ADR-032: Soft-delete retention + purge scheduler

**Status:** Accepted
**Date:** 2026-06-10
**Context:** The config has carried dormant `SoftDeleteConfig{Enabled,
RetentionDays}` and `PurgeConfig{Enabled, Schedule}` blocks that nothing reads.
Users, projects, and environments already soft-delete (GORM `DeletedAt`) with
restore endpoints, so soft-deleted rows accumulate forever with no lifecycle.

## Context

Soft delete is a safety net (a restore window after an accidental delete), but
without a purge step the rows live indefinitely. That is both a storage-hygiene
problem and a compliance one: GDPR/NIS2 erasure expects that a deleted record is
*actually* removed after a bounded grace period, not retained forever. Three
entities already soft-delete via `DeletedAt`: `users`, `projects`,
`environments`. (Secrets currently hard-delete and use a `Status` field, not
`DeletedAt` — giving secrets a `DeletedAt` soft-delete is a separate, larger
change that touches every secret query; it is a tracked follow-up, and the purge
scheduler will cover it for free once it lands.)

## Decision

Wire the dormant config into a **purge scheduler**: a background job that
hard-deletes soft-deleted rows whose `deleted_at` is older than the retention
window.

- **`SoftDeleteConfig.RetentionDays`** — the grace period; soft-deleted rows are
  purged once `deleted_at < now − RetentionDays`. Defaults to 30 days when unset.
- **`PurgeConfig.Enabled`** — opt-in. **Default off**: a hard delete is
  irreversible, so an operator must explicitly enable it. With it off the
  scheduler never runs and behaviour is unchanged (soft-deleted rows persist).
- **`PurgeConfig.Schedule`** — the run interval, parsed as a Go duration
  (e.g. `24h`, `6h`). Defaults to 24h.

A `KeyorixCore.PurgeExpiredSoftDeletes(ctx, before)` orchestrates per-entity
hard deletes (`PurgeDeletedUsersBefore` / `…ProjectsBefore` /
`…EnvironmentsBefore`, each `Unscoped().Where("deleted_at < ?").Delete`,
returning a count) and emits one **system-actored** `data.purged` audit event
with the counts. The scheduler goroutine in `main.go` mirrors the existing
anomaly-detection ticker (run-once-on-start + ticker + `ctx.Done()` shutdown),
guarded by `PurgeConfig.Enabled`.

Each entity is purged independently on its own `deleted_at` — no cascade logic
in the purge (a soft-deleted project's environments carry their own
`deleted_at` and are purged by their own query). This keeps the job simple and
idempotent.

## Consequences

- Operators get a real retention lifecycle: a configurable grace period, then
  permanent removal — the GDPR/NIS2 "erasure after grace" story, opt-in.
- Default-off means no behaviour change for anyone who doesn't enable it, and no
  surprise data loss.
- The purge is irreversible by design; the retention window is the only safety
  net, so the default (30 days, off) is conservative.
- Secrets soft-delete + restore (replacing the hard delete) is a follow-up; when
  it lands, adding `secret_nodes` to the purge is a one-line extension.
