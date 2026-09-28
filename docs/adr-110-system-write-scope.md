# ADR-110: `system.write` scope review — is the current 26-route grant narrow enough?

## Status

**Accepted** (Andrei, 2026-09-28). Program-plan Phase 6 follow-up to ADR-102
("Semantics and blast radius of the `system.write` capability", Proposed,
2026-09-05). This ADR resolves ADR-102's open (a)/(b) question for the
surface as it exists today — see "Relationship to ADR-102" below — and
records the per-route review the item asked for.

## Context

ADR-102 found that `system.write` gated 148 routes across nearly every
resource type in the product (the `/system` proxy tier, built for
`storage.type: remote` relay and never re-scoped as other things accreted
onto it) and declined to choose between treating that as intentional
break-glass (a) or a scoping defect needing a permission-scoping migration
(b).

That surface no longer exists. ADR-108 Phase 6 deleted the entire `/system`
proxy tier and `RemoteStorage` (steps 14b-2/14c-1/14c-2, PRs #2162/#2171,
merged). `internal/core/auth_bootstrap.go`'s own permission-catalog
description for `system.write` was updated in the same campaign to say so
directly:

> `#F6 (system-proxy-target-authority audit, 2026-09-21) through ADR-108
> Phase 6 (#2162/#2171): this permission USED TO also be the blanket gate on
> the entire /api/v1/system RemoteStorage-sync proxy route tree ... That
> entire route tree ... has since been deleted; system.write's actual
> footprint is now exactly the narrow use case this description names.`

This ADR verifies that claim against the live router (not just the comment)
and reviews whether any of the remaining routes can be narrowed further onto
an existing, more specific permission.

## What `system.write` gates today (verified 2026-09-28, `main` @ `341c30a2`)

`grep -c permSystemWrite server/http/router.go` → 26 matches: 1 constant
declaration + 25 gate call sites. Every call site, resolved to its route,
grouped by feature:

| # | Route(s) | What it mutates | Who legitimately needs it | Narrower existing permission? |
|---|---|---|---|---|
| 1–6 | `GET/POST/GET/PUT/DELETE /notification-channels[/{id}]`, `PUT /notification-channels/{id}/retry-policy` | Outbound alert-channel config (webhook/Slack/Teams/email URLs, retry policy) — where security/compliance alerts get sent | An install admin configuring where alerts go | None. No `notifications.write`/`.read` permission exists in the catalog (`defaultPermissions`, `auth_bootstrap.go`); the closest resource family is `system.*`. Splitting this into its own permission is a catalog change, not a reassignment — see "Not implemented" below. |
| 7–11 | `POST/GET/GET/PUT/DELETE /alert-escalation-policies[/{id}]` | Escalation policy definitions (severity threshold, minutes-until-escalate, target channel IDs) | Same persona as notification channels — configuring the alerting pipeline | Same as above: no narrower permission exists. |
| 12 | `POST /audit/checkpoint` | Writes a new audit-hash-chain checkpoint (tamper-evidence anchor) | An admin performing a scheduled/on-demand integrity checkpoint | None — this mutates the tamper-evidence dataset itself; `audit.read` (the group's own baseline gate) is deliberately a read-only tier one level below. |
| 13 | `POST /audit/migrate-chain-encoding` | One-time operator-triggered migration of the audit hash chain's on-disk encoding | Same bar as `/checkpoint` per its own adjacent comment: "it rewrites the tamper-evidence dataset itself" | None, same reasoning as #12. |
| 14 | `POST /audit/anomalies/{id}/acknowledge` | Marks a detected anomaly alert acknowledged/dismissed | An admin triaging anomaly alerts — a security-detection record mutation, not a routine audit-read action | None. Sits inside the `/audit` group's own `audit.read` `r.Use()`, so this route requires **both** `audit.read` and `system.write` (chi's `With()` adds to, not replaces, the group's `Use()` — same reasoning `permission_sweep_test.go`'s existing `GET /audit/anomalies` allowlist entry already documents for its sibling route). Effectively gated at the stronger of the two already. |
| 15 | `GET /admin/scheduler-metrics` | *(read, not a mutation — see note below)* | An operator who legitimately needs scheduler-tick timing visibility | `system.read` looks tempting (it's a `GET`), but this is the ONE route in the sweep where "narrower" and "safer" point in opposite directions: the route's own comment says the exact reason it isn't on the public `/metrics` endpoint is that a precise tick timestamp lets an unauthenticated caller predict a security-relevant job's next execution to sub-second precision — a timing side channel. `system.read` is the auto-granted baseline every user holds (ADR-021), so moving this there would be a **widening**, not a narrowing, of who can read it. Per this item's own instruction ("never widen"), left as `system.write`. Recorded here rather than silently passed, since a future reviewer will otherwise wonder why a GET is write-gated. |
| 16 | `POST /compliance/snapshots` | Triggers a full compliance-posture evaluation + persists a snapshot row | An admin/compliance officer capturing point-in-time evidence | None — the GET sibling (`ListComplianceSnapshots`) is already correctly on `audit.read`; the POST is deliberately one tier up per its own adjacent comment ("triggers a full evaluation + persist"). |
| 17–18 | `POST/DELETE /legal-hold` | Places/lifts a legal hold (ISO A.5.34) | Legal/compliance placing or lifting a preservation obligation | None — the GET sibling is on `audit.read`; place/lift is deliberately `system.write` per the adjacent comment ("an admin action, not a read disclosure"). |
| 19–21 | `POST /risk-exceptions`, `POST /risk-exceptions/{id}/approve`, `DELETE /risk-exceptions/{id}` | Risk-register (ISO A.5.8) create/approve/revoke | Risk owner/approver recording or closing an accepted risk | None — list is `audit.read`; create/approve/revoke is deliberately `system.write` per the adjacent comment. |
| 22–23 | `POST/DELETE /sod/policies[/{id}]` | Separation-of-duties policy CRUD (which permission pairs conflict) | Compliance defining SoD rules | None — reading policy *definitions* is baseline `system.read` (no PII, per the adjacent comment); creating/deleting the rule that other RBAC grants get checked against is deliberately one tier up. |
| 24 | `r.Use(permSystemWrite)` on `/admin/jobs` group (8 routes: `anomaly-alerts`, `rotation-reminders`, `expiry-reminders`, `compliance-digest`, `record-hygiene-snapshot`, `role-expiry-check`, `check-read-quotas`, `token-expiry-check`, `suspend-inactive-users`, `purge-audit-logs`) | On-demand triggers for background jobs that otherwise only run on their own schedulers | An admin forcing an immediate run after an incident or config change | None — every one of these is "do the thing the scheduler would otherwise do, right now," a deployment-wide administrative action with no narrower existing permission family (`admin_jobs.go`'s own handlers wrap core functions with no additional in-handler authorization, so the route gate is the only check). |
| 25 | `PUT /admin/anomaly-config` | Persists DB-backed anomaly-detection thresholds (lookback days, quarantine hours, ML tree count/sample size) | An admin tuning detection sensitivity | None — the GET sibling is correctly `system.read` (config values, no per-tenant data, same non-disclosure-sensitive family as `/system/auth-config` etc.); the PUT is a deployment-wide detection-tuning mutation with no narrower fit. |

Total: 25 distinct route-registration gate sites (one row above, #24, covers 8
of them via one group-level `r.Use()`) — 32 individual HTTP routes, all
inside the authenticated `/api/v1` group.

## Finding

**No clear-cut narrowing is available.** Every remaining `system.write`
route is either:

1. A genuine administrative mutation (checkpoint/migrate-chain-encoding,
   legal-hold place/lift, risk-exception approve/revoke, SoD-policy CRUD,
   anomaly-config tuning, on-demand job triggers) with no existing narrower
   permission in the catalog (`defaultPermissions`: `secrets.*`, `users.*`,
   `roles.*`, `audit.read`, `system.read`, `system.write`, `connect.*` — no
   per-resource `.write` tier for notifications/alerts/jobs/compliance
   exists today), or
2. Already correctly split from a narrower sibling within the same route
   family (every GET-vs-mutate pair reviewed above — compliance snapshots,
   legal hold, risk exceptions, SoD policies — already puts the read on
   `system.read`/`audit.read` and only the mutation on `system.write`).

The one apparent oversized-permission candidate (#15, scheduler metrics) is a
`GET` gated on a write permission, which looks backwards — but the fix
(`system.read`) would be a **widening** (every baseline user gains a timing
side channel the route's own design explicitly withholds from the
unauthenticated `/metrics` endpoint for exactly that reason). Per this item's
"never widen" instruction, left unchanged.

**Resolved by the Decision below (F1, 2026-09-28)** — see that section for
what shipped. The question as originally posed here: introducing brand-new,
finer-grained permissions (`notifications.write`, `alerts.write`, or similar)
to split rows 1–11 and 24 off `system.write` entirely. That is a genuine
option — those two feature families (notification/alert-channel config,
on-demand job triggers) are arguably a distinct "alerting operator" persona
from "manages compliance/legal/risk/SoD records" — but it expands the
permission taxonomy itself, which is a product decision (does this system
want an "alerting admin" role that is NOT also a compliance/audit admin?),
not a reassignment of an existing route onto an existing permission.

## Decision (Andrei, 2026-09-28)

**Yes** — a narrower "alerting operator" persona is wanted. Implemented as
F1 of the alerts/audit-gap session:

- New permission `alerts.write` added to `defaultPermissions`
  (`internal/core/auth_bootstrap.go`) — note the shipped name is
  `alerts.write`, not this ADR's earlier tentative `system.alerts.write`.
- New built-in role `alert_operator` (`alerts.write` only), seeded in
  `defaultRoles` for fresh installs and backfilled onto an already-initialised
  install by `internal/core/alerts_write_role_reconcile.go`'s
  `ReconcileAlertsWriteRole` (called from `server/main.go` alongside the other
  startup reconciles).
- `system.write` remains a **strict superset**, granted explicitly rather than
  checked implicitly at authorization time: the same reconcile function
  grants `alerts.write`, once, to every role already holding `system.write`
  (built-in or operator-defined custom role alike) via a one-time
  `system_metadata` completion marker
  (`alerts_write_role_backfill_v1`) — the same pattern
  `ReconcileUserBaselineRoles` uses for the `baseline_role_backfill_v1`
  marker (#2195). One-time, not an ongoing invariant: a later admin
  deliberately revoking `alerts.write` from a role that still holds
  `system.write` is respected, not silently undone on the next restart.
- Rows 1–11 (notification channels, alert-escalation policies) re-gated onto
  `alerts.write` in full.
- Row 24's `/admin/jobs` group gate was **split per-route**, not moved
  wholesale: each of the 10 job triggers was independently verified by
  reading its core-layer function (not assumed from its name) for whether it
  only ever emits/dispatches a notification, or actually mutates
  account/role/audit state. 8 moved to `alerts.write`
  (`anomaly-alerts`, `rotation-reminders`, `expiry-reminders`,
  `compliance-digest`, `token-expiry-check`, `run-alert-escalation`, and —
  contrary to this session's own initial expectation — `role-expiry-check`
  and `check-read-quotas`, both confirmed by reading
  `internal/core/role_expiry_notify.go`/`read_quota_alerts.go` to only emit
  `Notification` rows, never revoke a role grant or block a read). 3 stayed on
  `system.write`: `record-hygiene-snapshot` (persists a data row, not a
  notification), `suspend-inactive-users` (mutates account state),
  `purge-audit-logs` (deletes audit events).
- Incidental fix discovered while writing this decision's own behavioral
  test: `NotificationChannel`/`AlertEscalationPolicy` were never
  `AutoMigrate`d anywhere in `internal/storage/factory.go` — a fresh install,
  on any backend, would have hit "no such table" on every one of rows 1–11
  and `run-alert-escalation`, independent of which permission gated them.
  Fixed in the same bulk-migration list as the pre-existing `MFAStepUpGrant`
  fix right above it (same defect class).

### Final route table (post-decision, 2026-09-28)

| Route(s) | Permission | Notes |
|---|---|---|
| `GET/POST/GET/PUT/DELETE /notification-channels[/{id}]`, `PUT .../retry-policy` | `alerts.write` | Was rows 1–6 above. |
| `POST/GET/GET/PUT/DELETE /alert-escalation-policies[/{id}]` | `alerts.write` | Was rows 7–11 above. |
| `POST /audit/checkpoint` | `system.write` | Unchanged (row 12). |
| `POST /audit/migrate-chain-encoding` | `system.write` | Unchanged (row 13). |
| `POST /audit/anomalies/{id}/acknowledge` | `system.write` (+ group `audit.read`) | Unchanged (row 14). |
| `GET /admin/scheduler-metrics` | `system.write` | Unchanged (row 15) — moving to `system.read` would still be a widening. |
| `POST /compliance/snapshots` | `system.write` | Unchanged (row 16). |
| `POST/DELETE /legal-hold` | `system.write` | Unchanged (rows 17–18). |
| `POST /risk-exceptions`, `.../{id}/approve`, `DELETE .../{id}` | `system.write` | Unchanged (rows 19–21). |
| `POST /sod/policies`, `DELETE /sod/policies/{id}` | `system.write` | Unchanged (rows 22–23). |
| `POST /admin/jobs/anomaly-alerts` | `alerts.write` | Was part of row 24's group gate — notification-only. |
| `POST /admin/jobs/rotation-reminders` | `alerts.write` | Notification-only. |
| `POST /admin/jobs/expiry-reminders` | `alerts.write` | Notification-only. |
| `POST /admin/jobs/compliance-digest` | `alerts.write` | Notification-only. |
| `POST /admin/jobs/role-expiry-check` | `alerts.write` | Verified notification-only (no revocation) — moved despite not being on this session's initial expected list. |
| `POST /admin/jobs/check-read-quotas` | `alerts.write` | Verified notification-only (no read-blocking) — moved despite not being on this session's initial expected list. |
| `POST /admin/jobs/run-alert-escalation` | `alerts.write` | Verified notification-dispatch-only. |
| `POST /admin/jobs/token-expiry-check` | `alerts.write` | Notification-only. |
| `POST /admin/jobs/record-hygiene-snapshot` | `system.write` | Persists a data row, not a notification — stayed. |
| `POST /admin/jobs/suspend-inactive-users` | `system.write` | Mutates account state — stayed. |
| `POST /admin/jobs/purge-audit-logs` | `system.write` | Deletes audit events — stayed. |
| `PUT /admin/anomaly-config` | `system.write` | Unchanged (row 25). |

16 `system.write` gate sites, 19 `alerts.write` gate sites (see
`server/http/system_write_scope_test.go`/`alerts_write_scope_test.go` for the
enforcing allowlists).

## Relationship to ADR-102

ADR-102's Context section counted 148 routes reachable through the deleted
`/system` group and posed (a) break-glass-by-design vs. (b) routine-operator-
role-needing-narrower-permissions, declining to choose. That question was
posed against a surface that ADR-108 Phase 6 has since deleted outright — not
narrowed, deleted. The review above confirms the replacement surface (26
gate sites / 32 routes, all inside `/api/v1`, none of them a storage-relay
primitive) is a plausible size for **either** position: small enough that
(a) break-glass framing no longer describes an over-broad grant (nothing
here reaches machine-identity credentials, RBAC role grants, or account
state — the actual account-takeover-chain-enabling capabilities ADR-102's
Context section documented are gone with `/system` itself), and specific
enough that (b)'s "routine operator role" framing is now largely already
true of the remaining routes (compliance/legal/risk/SoD administration is a
coherent, narrow persona) modulo the one open sub-question above (should
alerting-config be split out further).

**ADR-102's registry entry is updated, not closed outright**: the original
148-route blast radius this ADR posed the question against no longer exists,
so that specific concern is resolved. The narrower question this ADR left
open (a dedicated alerting-operator permission) is resolved by the Decision
section above, not carried forward under ADR-102's original framing — no
`adr_open_decisions_tripwire_test.go` registry entry was ever added for it (an
inaccuracy in this ADR's earlier draft; corrected here rather than backfilling
a tripwire for a question that is now decided, not open).

## Guard

`TestSystemWriteRouteAllowlistCoversEveryGateSite`
(`server/http/system_write_scope_test.go`) fails if a *new* route is gated on
`system.write` without a corresponding allowlist entry naming what it
mutates and why `system.write` (not a narrower permission) is correct — the
same allowlist-with-reasoning convention `permission_sweep_test.go` already
uses for the `permSystemRead` sweep. Reuses that file's own AST walk
(`scanRouter`) rather than duplicating it.
`TestAlertsWriteRouteAllowlistCoversEveryGateSite`
(`server/http/alerts_write_scope_test.go`) is the same guard for the new
`alerts.write` sites, reusing the identical walk.
`TestAlertOperator_PermissionTiers`
(`server/http/alert_operator_permission_test.go`) is the behavioral
counterpart: a user holding only `alert_operator` succeeds on every
`alerts.write` route and is denied on every remaining `system.write` route.

## Consequences

- Notification-channel and alert-escalation-policy management, plus 8 of the
  10 `/admin/jobs` on-demand triggers, moved off `system.write` onto the new
  `alerts.write` — a real narrowing, not just a review. `system.write`
  remains a strict superset via a one-time backfill (see Decision above), so
  no existing holder lost access.
- Two guard tests now exist (`system_write_scope_test.go`,
  `alerts_write_scope_test.go`) so a *future* route added under either
  permission gets the same scrutiny this review gave the current 35 sites,
  rather than silently accreting again the way the original 148-route
  surface did.
- The "alerting operator" permission-taxonomy question this ADR originally
  deferred to Andrei's decision is now resolved (yes) — see Decision above.
