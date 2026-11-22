# Spec: opt-in sync report-in (#3450)

Status: DRAFT for review. Decision of record: Andrei, 2026-11-22, option a of #3450
("opt-in report-in with spec first"). No code in this PR; implementation follows the review.

## Problem

The suspend dialog offers "also clear synced Kubernetes copies" (#3215, #3221) but cannot
show where a secret is synced. The operator and `keyorix-k8s-sync` only read from Keyorix;
the server stores no cluster or target, so neither the dialog nor an incident responder can
see the blast radius of a leaked secret.

## Non-goals

- Reporting values, hashes of values or value lengths: never.
- Replacing the operator's own Secret cleanup. Clearing copies keeps working through the
  suspension marker (`internal/core/secret_suspend.go`); this only adds visibility.
- Default-on reporting (option b of #3450 was not chosen).
- Reporting from agents that are not Keyorix's own (ESO, third-party tools).

## User journeys

1. Operator or k8s-sync is installed with `reportIn.enabled=true` (default false). After each
   successful sync of secret S into target Secret `ns/name` of cluster `C`, it reports one
   record. Nothing is sent when the flag is off, and the agent says so once at startup.
2. A user opens the Suspend dialog of S. If the caller may read S, the dialog lists the known
   targets (cluster id, namespace, target Secret, last reported, `stale` flag). If there are
   none it says "no sync agent has reported this secret; copies may still exist" (an empty
   list is not proof of absence).
3. An incident responder calls the same list over REST/CLI to see the blast radius.
4. When a secret is deleted or an agent stops mapping it, the agent reports removal; otherwise
   the row ages out (below).

## API contract (OpenAPI diff, to be implemented)

- `PUT /api/v1/secrets/{id}/sync-targets` body `{cluster_id, namespace, target_name, agent}`.
  Upsert on `(secret_id, cluster_id, namespace, target_name)`; sets `last_reported_at` from the
  SERVER clock (never the agent's). `agent` is `operator` or `k8s-sync`. Max lengths: cluster id
  63, namespace 63, target 253 (Kubernetes limits); rejected with 400 beyond them or on characters
  outside the Kubernetes name alphabet.
- `DELETE /api/v1/secrets/{id}/sync-targets?cluster_id=..&namespace=..&target_name=..` removes one
  row; idempotent (204 whether or not the row existed).
- `GET /api/v1/secrets/{id}/sync-targets` returns `{targets:[{cluster_id, namespace, target_name,
  agent, first_reported_at, last_reported_at, stale}]}`, `stale` computed server-side.
- gRPC mirrors (`ReportSyncTarget`, `RemoveSyncTarget`, `ListSyncTargets`) in the same PR as REST,
  per the one-contract rule. Web (suspend dialog) and CLI (`keyorix secret sync-targets <id>`)
  are updated in the implementing PRs and linked.

## Authorization

- Report/remove: a machine identity whose scoped permission includes the NEW permission
  `secrets.sync_report` AND which can already read the secret (same scope check as the value
  read it performs; `authorizeSecretScoped`). A token that cannot read S gets the same answer
  as for an unknown S (no existence oracle). The permission is not part of any built-in role
  until the operator chart's documented identity recipe adds it.
- List: caller needs `secrets.read` on S (`permSecretsRead`). The list never discloses a target
  for a secret the caller cannot read.
- Tenancy and project scoping follow S; `cluster_id` is a label the agent chooses, not an
  identity: two agents can claim the same id, so the UI shows it as "reported by", not
  "verified".

## Data model

Table `secret_sync_targets(id, secret_id FK ON DELETE CASCADE, cluster_id, namespace, target_name,
agent, reporter_machine_id, first_reported_at, last_reported_at)` with a UNIQUE index on
`(secret_id, cluster_id, namespace, target_name)`. Additive migration, no backfill; old binaries
ignore it (rolling-upgrade columns doc applies: new table only).

## Staleness

`stale = now - last_reported_at > 3 * reportIn.interval`, with the agent's interval sent as
`interval_seconds` (clamped server side to 60..86400) so the server needs no agent config. Stale
rows stay visible, marked "last known"; a purge job deletes rows not reported for 30 days (config
`secrets.sync_targets.retention_days`, default 30). Suspended secrets keep their rows: that is the
case the feature is for.

## Audit

- Each report that creates a row or changes `agent` writes `secret.sync_target_reported`; a
  heartbeat that only refreshes `last_reported_at` is NOT audited (volume), and says so in the doc.
  Removal writes `secret.sync_target_removed`. Listing writes nothing beyond the normal access log.
- Audit and row change commit in one transaction (INV-CORE-security-mutation-audit-same-tx
  pattern); a failed audit fails the report, and the agent retries.

## Failure and concurrency cases

- Agent reports while the secret is deleted or purged: 404, the agent drops its record.
- Two replicas of the agent report the same target: the upsert is idempotent; last write wins on
  `last_reported_at`.
- A report lands between a suspend and its clear-copies pass: the list is read-only information, so
  the clear pass does not depend on it and cannot be starved by it.
- Report endpoint down: the agent logs and retries with backoff; sync itself is never blocked by a
  failed report (reporting is best effort for the agent, but never silent: it logs each failure).
- Hostile agent: it can only add rows for secrets it can already read, bounded by a per-secret cap
  of 256 targets (409 beyond it) so a compromised identity cannot bloat the table.

## Acceptance criteria

1. With `reportIn.enabled=false` the agents make zero calls to the new endpoints (test on both).
2. A report for a secret the identity cannot read is indistinguishable from an unknown secret.
3. The list excludes unreadable secrets and never contains a value.
4. Heartbeat does not write an audit row; first report and removal do, in the same transaction.
5. Staleness flips exactly at 3x interval; rows older than retention are purged.
6. Suspend dialog shows targets, the empty-list wording, and stale marking (real-backend
   Playwright spec).
7. Per-secret cap and name-length limits return 409 and 400.

## Open questions for the reviewer

- Should `cluster_id` default to the `kube-system` namespace UID so ids are unique without
  operator configuration? Recommendation: yes, with an override.
- Should the list also be offered in the secret's detail page, not only the suspend dialog?
  Recommendation: yes, later PR.

## Implementation split (each a small PR)

1. Storage + migration + core (table, upsert, list, purge) with tests.
2. REST + gRPC + OpenAPI + permission.
3. Agents (operator, k8s-sync) behind `reportIn.enabled`.
4. Web suspend dialog and CLI.
