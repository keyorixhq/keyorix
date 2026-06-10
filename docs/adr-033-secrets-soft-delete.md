# ADR-033: Secrets soft-delete + restore

**Status:** Accepted
**Date:** 2026-06-10
**Context:** Users, projects, and environments soft-delete via GORM `DeletedAt`
with restore endpoints and are covered by the ADR-032 purge scheduler. Secrets
were the exception: `SecretNode` had no `DeletedAt`, so `DeleteSecret`
**hard-deleted** the row immediately — no recycle bin, no restore, and nothing
for the purge scheduler to govern.

## Context

A secret is the highest-value object in the system; an accidental delete with no
undo is the worst footgun. Giving `SecretNode` a `DeletedAt` brings it in line
with every other entity: a delete becomes reversible within the retention
window, then the purge scheduler erases it permanently.

The catch is GORM's soft-delete scoping. Once `SecretNode` has `DeletedAt`,
GORM auto-adds `deleted_at IS NULL` to **model-based** queries
(`db.Model(&SecretNode{})`, `Find`, `First`, `Delete`), but **not** to raw /
`Table` / `Joins` SQL. An audit found six raw queries that touch `secret_nodes`
and would otherwise leak soft-deleted secrets into results.

## Decision

Add `DeletedAt gorm.DeletedAt` to `SecretNode` (additive, `columnExists`-guarded
migration). Consequences, all handled:

- **`DeleteSecret` and the `DeleteProject` cascade become soft automatically** —
  both already call `db.Delete(&SecretNode{})`, which GORM turns into a
  `deleted_at` stamp once the field exists. The `DeleteProject` restore path now
  also clears secrets' `deleted_at` (it previously, incorrectly, assumed secrets
  were hard-deleted).
- **`RestoreSecret`** (`Unscoped().Where("id = ? AND deleted_at IS NOT NULL").
  Update("deleted_at", nil)`) + `POST /api/v1/secrets/{id}/restore`, mirroring
  the user/project restore endpoints.
- **List with `?include_deleted=true`** (`SecretFilter.IncludeDeleted` →
  `Unscoped()`), so a restore UI can surface deleted secrets; the response
  carries `deleted_at`.
- **The six raw queries get an explicit `s.deleted_at IS NULL`**:
  `ListProjectsWithCounts` (count/last-activity), `MostAccessedSecrets`,
  `UnusedSecrets`, `ListProjectSecretsForDrift`, and the two `ListSharedSecrets`
  joins. Without these, deleted secrets would inflate counts and appear in
  usage/drift/shared views.
- **Purge coverage**: `PurgeDeletedSecretsBefore` joins the ADR-032 scheduler, so
  a soft-deleted secret older than the retention window is permanently removed
  alongside users/projects/environments.

The pre-existing `Status` field (active/expired business state) is orthogonal to
`DeletedAt` (existence) and is left as-is.

## Consequences

- Deleting a secret is now reversible within the retention window — a real
  safety net for the most dangerous operation in the product.
- The blast radius of GORM auto-scoping is contained to the six audited raw
  queries; all other secret access is model-based and filters automatically.
- Soft-deleted secrets never appear in lists, counts, usage analytics, drift,
  or shared-with-me views, and are erased by the purge scheduler on schedule.
