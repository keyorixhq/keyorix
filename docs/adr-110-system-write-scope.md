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

**Not implemented, and out of scope for this ADR:** introducing brand-new,
finer-grained permissions (`notifications.write`, `alerts.write`, or similar)
to split rows 1–11 and 24 off `system.write` entirely. That is a genuine
option — those two feature families (notification/alert-channel config,
on-demand job triggers) are arguably a distinct "alerting operator" persona
from "manages compliance/legal/risk/SoD records" — but it expands the
permission taxonomy itself, which is a product decision (does this system
want an "alerting admin" role that is NOT also a compliance/audit admin?),
not a reassignment of an existing route onto an existing permission. **NEEDS
ANDREI**: is a narrower "alerting operator" persona (notification channels +
escalation policies + on-demand job triggers, without compliance/legal/risk/
SoD authority) something the product wants? If yes, this is follow-up work:
add `system.alerts.write` (or similar) to `defaultPermissions`, re-gate rows
1–11 and the job-trigger routes onto it, and decide whether `system.write`
holders should also implicitly retain it (likely yes, as a superset) or need
both grants explicitly.

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
so that specific concern is resolved. The narrower question this ADR leaves
open (a dedicated alerting-operator permission) is tracked as this ADR's own
open item, not carried forward under ADR-102's original framing — see
`internal/core/adr_open_decisions_tripwire_test.go`'s updated entry.

## Guard

`TestSystemWriteRouteAllowlistCoversEveryGateSite`
(`server/http/system_write_scope_test.go`) fails if a *new* route is gated on
`system.write` without a corresponding allowlist entry naming what it
mutates and why `system.write` (not a narrower permission) is correct — the
same allowlist-with-reasoning convention `permission_sweep_test.go` already
uses for the `permSystemRead` sweep. Reuses that file's own AST walk
(`scanRouter`) rather than duplicating it.

## Consequences

- No code change to any route's permission gate — the review found every
  current grant either already correctly scoped or lacking a catalog
  permission narrow enough to reassign onto.
- A guard test now exists so a *future* route added under `system.write`
  gets the same scrutiny this review gave the current 26, rather than
  silently accreting again the way the original 148-route surface did.
- The "alerting operator" permission-taxonomy question is deferred to
  Andrei's decision, not resolved here.
