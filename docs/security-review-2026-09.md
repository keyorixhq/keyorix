# Security review, 2026-09: ambient state, failure paths, and egress

This document records a full reconciliation of a security-hardening review that ran through late August and into
early September 2026 — 75 tracked issues, spanning everything from a single-line CSP directive to a multi-replica
authorization race. Its purpose is to state, plainly and for someone who was not in the room, what question drove
the review, what it found, what got fixed and how the fix is enforced going forward, and what is still open.

It is written after independently re-verifying every issue's closure against the actual state of `origin/main` —
not against what the tracker says, not against what a prior summary claimed. That distinction mattered: one issue
in this set (#1494) was closed with a broken closing comment that contradicted its own investigation's
recommendation to keep it open. It has been reopened and correctly cross-referenced to the architectural decision
that actually governs it (ADR-084). That correction, and the discipline behind it, is described in full below.

## Method

Two questions generated the class list this review worked from, and they are the reusable part — the part that
makes this review repeatable by someone else rather than a one-off pass over a list someone happened to write down.

**What ambient state does the process inherit and never normalise?** A server process inherits a wall clock, a
working directory, a file-creation umask, and whatever identity happens to be attached to the caller of any given
function deep in a call chain. None of these are validated at the point they're consumed — they're just trusted.
This question is what produced the wall-clock-trust sweep (an absolute expiry timestamp compared against
`time.Now()` assumes the clock never runs backward — it can, on VM migration, NTP correction, or manual
intervention, and when it does, every such comparison silently extends whatever it was supposed to expire), the
config/storage-path-resolution findings (a relative path resolves against the process's current working directory,
which is not the same thing as "the directory the config file lives in," and two server processes launched from
different directories with the same config file will silently open two different databases), the file-permission
finding (a database file created without an explicit mode inherits whatever umask the parent shell happened to
have), and the actor-attribution sweep (a machine identity acting through a code path written for human users
loses its own identity at whichever layer never learned that machines exist, and the record left behind attributes
the action to nobody, or to the wrong somebody).

**What would silently falsify the product's claim?** Keyorix's central claim is that access to a secret is
mediated by a permission check. Anything that lets an authorized-looking response happen through a path that
skipped the check falsifies that claim without ever producing an error a monitoring system would catch. This
question is what produced the raw-storage-bypass sweep (a `/system`-prefixed HTTP proxy route that writes directly
to the storage layer instead of going through `internal/core`'s own invariant-enforcing functions is a real,
silent bypass of every check `internal/core` would otherwise apply), the existence-oracle finding (a 404 that means
"doesn't exist" on one route and a 404 that means "exists, you can't see it" on another route lets an
authenticated-but-unauthorized caller learn what they were denied learning), the role-creation core-bypass
(the same shape as raw-storage-bypass, but for the RBAC role-definition path itself), and the multi-replica-safety
finding (an invariant enforced only by an in-process mutex is, in a single-replica deployment, a real guarantee —
and in a horizontally-scaled one, decoration, because two replicas' mutexes know nothing of each other).

Both questions were applied by reading real code paths end to end — tracing a request from its route registration
through every layer to its storage write or read — rather than pattern-matching on function names or scanning for
known-bad idioms. Several findings below only exist because a "this looks fine" read was pushed one layer further:
the raw-storage-bypass guard test that was itself only checking 18 of the routes it claimed to cover; the
actor-attribution fix that looked complete after covering the six call sites the issue named, until a repo-wide
walk found two more.

## Classes examined

Every class below was actually investigated — including the ones with no fix attached, which came back clean and
are recorded as such. A review that only lists hits reads identically to one that never looked at everything else.

| Class | Result |
|---|---|
| Raw-storage-bypass proxies (`/system` routes skipping `internal/core`) | **16 issues, fixed** (#1524, #1529, #1542, #1545–#1547, #1551–#1552, #1572, #1578–#1580, #1585–#1587, #1593), plus a follow-up sweep confirming no further live extent (#1592). The guard mechanism itself widened from 18 hand-picked routes to the full route surface. Governed by ADR-088. |
| Machine/human actor attribution (audit + model fields) | **4 issues, fixed** (#1530, #1573, #1623, #1626); one further candidate investigated and confirmed by-design, no gap (#1621). Governed by ADR-091, ADR-092. |
| Wall-clock trust (absolute expiry checks) | **2 issues, fixed** (#1632, #1653), covering 8 individual call sites across auth sessions, OIDC, Connect, classification-gate approvals, and shares. Governed by ADR-094. |
| RemoteStorage wire-call completeness (dead/stub/unverifiable RPCs) | **5 issues, fixed** (#1511, #1540, #1541, #1576, #1589), including rebuilding the detection guard from regex to structural AST matching after it was found blind to 13 of its own population. Governed by ADR-087. |
| CI-exclusion drift (packages silently dropped from CI) | **3 issues, fixed** (#1533–#1535) — re-included, and the underlying exclusion-justification mechanism made machine-checked rather than merely asserted. |
| Reconcile / permission-catalog drift (`ReconcileRBACPermissions`, `adminPermissions` vs. `defaultPermissions`) | **2 issues, fixed** (#1497, #1500); a third confirmed the additive-only reconcile behavior is intentional per ADR-044, not a gap (#1496). |
| Existence-oracle consistency (404-vs-403) | **1 issue, fixed** (#1645) — a house convention (ADR-096) plus an incremental, independently-testable migration, not a single patch. |
| Role-creation core-bypass | **1 issue, fixed** (#1660). |
| Multi-replica safety (mutex-only invariants) | **1 issue, fixed** (#1646), covering 6 named invariants. |
| RBAC admin-detection structural integrity | **1 issue investigated, decision recorded (ADR-084), implementation deliberately deferred** (#1494) — see "What remains open." |
| Identity normalisation (Unicode NFC/NFD collision) | **1 issue, fixed** (#1642). |
| File-creation permissions (umask inheritance) | **1 issue, fixed** (#1647). |
| Request-context lifecycle (audit durability across client disconnect) | **1 issue, fixed** (#1650). |
| Config/storage load robustness (path resolution, parse-error handling) | **2 issues, fixed** (#1636, #1644). Governed by ADR-095. |
| Supply-chain / CI tooling hardening (GitHub Action env-injection, mis-based-merge detection) | **2 issues, fixed** (#1355, #1613). |
| Secret-material-in-logs sweep | **1 issue investigated** (#1643) — production paths clean; one dead-code gap in an orphaned developer tool, closed by deleting the tool. |
| RemoteStorage stub reachability (risk-exceptions, project-membership) | **2 issues investigated** (#1512, #1584) — both confirmed unreachable in every real deployment topology, no fix needed. |
| Content-Security-Policy `style-src unsafe-inline` | **2 issues investigated** (#1273, #1302) — accepted, documented risk, not a regression. |
| Mutation-testing efficacy alerts | **2 issues investigated** (#1354, #1461) — both self-admitted tooling artifacts (synthetic test fixtures), not real regressions. |
| `internal/core` package-size / organisational debt | **1 issue investigated** (#1523) — deliberately deferred (won't-fix-now), explicit reopen trigger recorded. |
| RBAC built-in-role audit completeness, raw-map call-site hazards, BeforeSave-bypass fixtures | **3 issues, fixed** (#1503, #1507, #1619). |
| Individual findings not part of a recurring class | **18 issues, fixed or resolved** — Connect subsystem input/config validation (#1475–#1477, #1479), deployment/CLI hardening (#1334, #1521), a flaky test (#1504), dead-code removal following an unreachability proof (#1480, #1640, #1641), documentation drift (#1325, #1478, #1649), a timestamp-normalization fix (#1492), two authorization-gap fixes outside the main proxy-bypass sweep (#1531, #1648), a scoped, disclosed mitigation for a RemoteStorage RBAC-primitive gap (#1575), and one accepted test-only/non-production-reachable flake (#1509). |

## What was found and fixed

The detail lives in the full reconciliation table (issue-by-issue, with commit SHAs and file:line citations,
independently re-verified against `origin/main`) rather than reproduced here. Of the 75 tracked issues, 63
resulted in a code, test, or guard change; the remaining 12 were legitimate no-code closures —
confirmed-safe-by-design, accepted risk, or tooling noise, each with its own recorded reasoning rather than a bare
"closed."

The two shapes worth calling out specifically, because they recurred across many individual findings rather than
being one-offs:

- **The raw-storage-bypass class is closed by a guard, not by a fixed list.** Individually fixing each `/system`
  proxy route that skipped `internal/core` would have left the next one unguarded. The actual closing mechanism —
  `TestNoUnjustifiedRawStorageBypass` (`server/http/raw_storage_bypass_guard_test.go`) — walks every registered
  route and its one-hop call graph, and fails if a scoped-resource route doesn't reach a `core.KeyorixCore` method.
  It started at 18 hand-picked routes and now covers the full 500+ route surface. New routes are checked by
  construction, not by remembering to re-run a sweep.
- **The 404-vs-403 existence-oracle finding produced a house convention, not a single patch.** ADR-096 states the
  rule (403-for-both, with a narrow, precisely-scoped real-404 exception for a caller holding the same permission
  globally) and the shared mechanism every scoped-resource route is migrated onto. The migration is intentionally
  incremental — each site's migration is independently reviewable and testable — and the ADR itself records which
  sites remain, so "partially migrated" is a documented, tracked state, not a silently abandoned one.

## What remains open

Two items, both **deliberately deferred** — a decision was made in each case, and the reason still holds. Neither
is scheduled-but-undone, and neither was found to be missed.

- **#1494 / ADR-084 — replace name-based admin-role detection with a structural `bypasses_permission_checks`
  column.** The live exploit surface this issue originally worried about (creating or renaming a role to acquire
  the four reserved admin names) is closed today by an independent, structural guard
  (`TestUpdateRoleRequest_CarriesNoNameField` — neither transport's update path can rename a role at all, so
  there is no rename-based bypass to begin with). ADR-084 records the decision on the more resilient
  long-term mechanism, with alternatives considered and rejected, and explicitly defers implementation as
  not-urgent follow-up work — correctly so, since there is no live gap forcing an earlier timeline. This issue
  was closed once, contrary to its own investigation's recommendation, with a corrupted closing comment; it has
  been reopened, retitled to name ADR-084 directly, and the record corrected.
- **#1653 — six wall-clock ceiling sites named, one (`break_glass.go`'s activation listing) left unfixed.** The
  fixing commit disclosed this omission explicitly rather than silently claiming full coverage, with the
  reasoning that the actual access grant a break-glass activation represents is a role assignment, and role
  assignments are already covered by the RBAC-invariant clock-watermark fix (#1651) — independently corroborated
  during this reconciliation by tracing `RemoveUserRole`'s call path against the same watermark check. The
  `BreakGlassActivation.State` field the original issue named is a reporting label on top of that already-guarded
  grant, not an independent access-control decision point.

No item in this review's scope was found to be *believed closed and isn't* with no available explanation, and
none was found *filed and then lost track of* with no resolution at all — the two items above both have a stated,
current, defensible reason, which is the difference between "deliberately deferred" and "missed."

## What was deliberately not examined

This review's scope was defined by the ambient-state and silent-falsification questions above, applied to the
server, CLI, storage, RBAC, and CI/supply-chain surfaces. The following were explicitly out of scope, and are
named here so that omission reads as a stated boundary rather than an implied "checked, fine":

- **Memory zeroization.** Whether secret material is scrubbed from process memory after use (versus left for the
  garbage collector, or a swapped page, to eventually reclaim) was not examined. Go's runtime and garbage collector
  make this a substantially harder guarantee to make than it is in a language with manual memory management, and
  doing it properly is a distinct piece of work with its own design tradeoffs, not a fix-sized finding.
- **Migration downgrade paths.** This review's wall-clock and path-resolution findings touch storage and config
  loading, but whether a downgrade (running an older binary against a database a newer version has migrated)
  fails safely was not tested. The existing migration system's `down` migrations were touched by an earlier,
  separate piece of work (adding pre-drop backups) that predates this review and is not re-verified here.
- **Availability and denial-of-service resistance**, beyond the specific multi-replica-mutex finding recorded
  above. Rate limiting, resource-exhaustion bounds on individual endpoints, and general load-shedding behavior
  were not swept as their own class in this pass.
- **Cryptographic primitive choice and key-management lifecycle** (rotation cadence, HSM/KMS integration
  correctness) — this review's scope was request-path and process-lifecycle behavior, not the cryptography
  underneath it.
- **The frontend (`web/`) beyond its CSP configuration**, which surfaced incidentally via the accepted-risk CSP
  finding above and was not otherwise part of this pass's sweep.

## Governing ADRs

ADR-084 (admin-bypass structural marker, deferred implementation), ADR-087 (RemoteStorage deletion pass),
ADR-088 (system proxy layer design), ADR-091 (machine `CreatedBy` attribution classification), ADR-092 (audit
event `UserID` for a machine principal), ADR-093 (remote `--by`-authority check), ADR-094 (time handling: UTC
internally, wall-clock distrust), ADR-095 (database path resolution), ADR-096 (anti-enumeration, 403-for-both).
