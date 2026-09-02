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
| Wall-clock trust (absolute expiry checks) | **2 issues, fixed** (#1632, #1653), covering 8 individual call sites across auth sessions, OIDC, Connect, classification-gate approvals, and shares. #1653's break-glass site was reopened and genuinely fixed 2026-09-02 — see "Update" below; its original closure's stated reason for deferring that one site did not hold up. Governed by ADR-094. |
| RemoteStorage wire-call completeness (dead/stub/unverifiable RPCs) | **5 issues, fixed** (#1511, #1540, #1541, #1576, #1589), including rebuilding the detection guard from regex to structural AST matching after it was found blind to 13 of its own population. Governed by ADR-087. |
| CI-exclusion drift (packages silently dropped from CI) | **3 issues, fixed** (#1533–#1535) — re-included, and the underlying exclusion-justification mechanism made machine-checked rather than merely asserted. |
| Reconcile / permission-catalog drift (`ReconcileRBACPermissions`, `adminPermissions` vs. `defaultPermissions`) | **2 issues, fixed** (#1497, #1500); a third confirmed the additive-only reconcile behavior is intentional per ADR-044, not a gap (#1496). |
| Existence-oracle consistency (404-vs-403) | **1 issue, fixed** (#1645) — a house convention (ADR-096) plus an incremental, independently-testable migration, not a single patch. |
| Role-creation core-bypass | **1 issue, fixed** (#1660). |
| Multi-replica safety (mutex-only invariants) | **1 issue, fixed** (#1646), covering 6 named invariants. |
| RBAC admin-detection structural integrity | **1 issue, fixed** (#1494) — decision recorded in ADR-084, implemented 2026-09-02. See "Update, 2026-09-02" below; deferred at the time this table was first written. |
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

None, as of 2026-09-02. Two items were listed here at earlier points in this document's life — #1494/ADR-084 and
#1653 — both since resolved. Neither is re-described here; each is a pointer to "Update, 2026-09-02" below, so
this section states current reality rather than repeating a now-superseded claim.

#1653 is worth a specific flag, though: it wasn't a deferral whose reason simply expired — its stated premise was
independently tested and found false. That distinction matters for reading the rest of this document. Every OTHER
deferral recorded in this review (the CMK-rotation and memory-zeroization items in the "Update" section below,
for instance) rests on a premise stated in prose, the same way #1653's did, and none of the others have been
independently re-tested the way #1653's was. Confirming #1653's premise was false on the first deliberate check
is a data point, not a coincidence to wave off — a follow-up pass enumerating each remaining deferral's
load-bearing premise and checking whether anything actually asserts it (matching #1653's own "guard the premise,
not the conclusion" investigation) is recommended, not yet done.

No item in this review's scope was found to be *believed closed and isn't* with no available explanation, and
none was found *filed and then lost track of* with no resolution at all — every deferred item, past and present,
had a stated, current, defensible reason, which is the difference between "deliberately deferred" and "missed."
#1653 is the one exception on record: its stated reason did not hold up, and is corrected below rather than left
standing.

## What was deliberately not examined

This review's scope was defined by the ambient-state and silent-falsification questions above, applied to the
server, CLI, storage, RBAC, and CI/supply-chain surfaces. The following were explicitly out of scope, and are
named here so that omission reads as a stated boundary rather than an implied "checked, fine":

- **The frontend (`web/`) beyond its CSP configuration**, which surfaced incidentally via the accepted-risk CSP
  finding above and was not otherwise part of this pass's sweep.

## Update, 2026-09-02: follow-up investigations

Changes since this document was first written, recorded here rather than silently folded into the sections
above, for the same reason #1494's original mis-closure is narrated rather than quietly fixed: a review document
that edits its own past claims without a visible trail is exactly the failure mode this document exists to avoid.

- **#1494 / ADR-084 implemented.** `models.Role.BypassesPermissionChecks`, resolved by role ID via
  `storage.RoleSetBypassesPermissionChecks`, now replaces `roleSetContainsAdmin`'s old fixed-name lookup at all
  8 call sites (`authz.go` ×5, `dynamic_secrets.go`, `invitations.go`, `scim_groups.go`). Written only by role
  seeding (`defaultRoles`/`BootstrapSystem`) and a one-time migration snapshot for existing installs;
  `CreateRole`/`UpdateRole` never accept it from a request DTO on any transport, matching the ADR's decision.
  `installAdminRoleIDSet` and `isAdminRoleName`/`adminRoleNames` remain unchanged, per the ADR's explicit scope.
  This is no longer an open item.
- **Migration downgrade paths, examined (ADR-097).** Tracing the security-relevant columns `migrateDatabase`
  has added to date (`roles.bypasses_permission_checks`, `user_roles`/`group_roles.environment_id`,
  `secret_nodes.classification` and its siblings, `audit_events.prev_hash`/`entry_hash`) through their actual
  authorization/verification call sites found every one of them defaults in the safe direction if an older
  binary — one that doesn't know the column exists — writes a new row. That holds only because each migration's
  author independently chose the correct default; nothing enforced it. ADR-097 adds a schema-epoch startup guard
  (`checkSchemaEpoch`/`recordSchemaEpoch`, `internal/storage/factory.go`) so a binary older than the database
  it's pointed at refuses to start rather than silently running against unknown state — closing the class,
  matching this review's own stated preference for a guard over a per-instance audit.
- **Availability and denial-of-service resistance, investigated.** Mapped existing defenses first (rate limiting,
  payload/timeout bounds, pagination, bulk-op batch caps) — found mature and consistently fail-closed, with one
  gap: `transitiveDependents` (`internal/core/secret_dependencies.go`), the BFS backing `GetSecretImpact`/
  `GetSecretImpactPreview`, had no node or depth cap — unlike its sibling `blastBFS` (`blast_radius.go`), which
  bounds both for the same reason (#G44: a per-node authorization check afterward makes an unbounded node count a
  per-request cost multiplier). Fixed to match `blastBFS`'s exact bound shape, with a `Truncated` flag so a capped
  result is never silently reported as complete (#G24 discipline).
- **Cryptographic key-management lifecycle, investigated — clean, no fix needed.** Traced the DEK/KEK envelope
  hierarchy, KMS/HSM provider integration (`internal/crypto/`), and DEK rotation/re-encryption sweep
  (`internal/encryption/`) against this review's own methodology (does a provider failure fail closed; is a
  partial/interrupted operation loud or silently absorbed). Found consistently fail-closed and well-guarded: a KMS
  provider failure refuses server startup; a weaker-fallback key-provider chain requires an explicit opt-in and
  logs+audits its own use; DEK rotation is atomic (one DB transaction, all-or-nothing, no partially-swept state
  possible) with an orphaned-pending-file cleanup on crash; and sweep completeness (every DEK-encrypted model field
  has a corresponding re-encryption sweep) is enforced by a structural AST-parsing guard
  (`internal/encryption/sweep_completeness_test.go`), not a hand-maintained list. Two in-code "already fixed"
  claims (Azure Key Vault key-version pinning against rotation; the historical MFA/dynamic-secret sweep-omission,
  #422) were independently re-verified by running their dedicated tests rather than trusted at face value — both
  genuinely hold. The one real open item, cloud-KMS CMK rotation being entirely outside Keyorix's management, is
  already explicitly recorded as deferred in ADR-041's own scope — a stated boundary, not a gap this pass found.
- **Memory zeroization, investigated — partial fix, one real gap remains open by design.** Traced where secret
  material actually lives in process memory. What's genuinely protected: the master KEK (wiped in place
  immediately after use) and the DEK plus its two KEK-derived siblings — the evidence-signing key and the
  audit-checkpoint key — all wiped on graceful shutdown and DEK rotation via a real byte-by-byte overwrite
  (confirmed empirically: the Go compiler lowers `for i := range b { b[i] = 0 }` to a genuine
  `runtime.memclrNoHeapPointers` call, not eliminated — an initial hypothesis that this needed `runtime.KeepAlive`
  protection against compiler dead-store elimination did not hold up under a direct compile-and-disassemble check,
  and was dropped rather than "fixed" as cargo-culting). Two real test-coverage gaps were found and fixed:
  `TestEvidenceSignKey_WipedOnShutdown`/`TestAuditCheckpointKey_WipedOnShutdown` only asserted the public getter
  returned `ok=false` post-wipe — which only proves the field reference was nilled, since the getter always returns
  a copy, not the real backing array. A `Wipe()` regression that dropped its `wipeBytes()` call but kept the
  nil-assignment would have passed both tests unchanged. Rewritten to the same memory-scan style
  `TestServiceShutdown_WipesEncryptionServiceDEK` already uses for the DEK (capture the real backing array before
  wipe, assert all-zero after) and confirmed by mutation: reintroducing the exact dropped-`wipeBytes` regression
  made both new tests fail as expected. **What remains genuinely unprotected, and why it's a design gap rather
  than a fix-sized one** (confirming this document's original framing): every secret-VALUE plaintext accumulates
  at least three unwiped heap copies between decryption and the wire (the `gcm.Open` output, a `string()`
  conversion — Go strings are immutable and cannot be zeroed once created — and a JSON/protobuf serialization
  buffer), by construction of `encoding/json`'s and Go strings' own APIs, not from a missed call site; closing it
  would mean threading `[]byte`-only plaintext through the entire read path and abandoning string-based
  serialization for secret fields. The master passphrase (`KEYORIX_MASTER_PASSWORD`) is string-shaped from
  `os.Getenv` onward and, like any Go string, structurally cannot be wiped at all. Neither gap has a workable
  fix within this pass's scope; both are recorded here as open, not silently left where "not examined" implied
  no one had looked.
- **#1653's break-glass deferral, premise tested and found false — reopened and genuinely fixed.** #1653's
  original closure deferred one of six wall-clock sites (`break_glass.go`'s activation listing) on the stated
  premise that `BreakGlassActivation.State` is "a reporting label... not an independent access-control decision
  point." Asserting that premise directly (guard #1653 itself asked for but the closure never wrote) found it
  false: `core.RevokeBreakGlass`'s guard, and its remote-storage-proxy mirror
  (`RevokeBreakGlassActivationProxy`), both read `State` to decide whether to attempt the real de-authorization
  action, so a wall-clock hiccup in the deferred site's read-path write could silently block a legitimate
  emergency revoke. The mirror direction also held: a genuinely-expired-but-never-revisited row stayed
  `state='active'` in the database indefinitely, permanently occupying the DB-level one-active-slot-per-
  (project,user) partial unique index and blocking a legitimate NEW activation — reproduced directly
  (`TestActivateBreakGlass_ReactivatesAfterNaturalExpiry` fails once the real production index is added to its
  fixture, which it wasn't). Both directions disable the control break-glass exists for, bounded by TTL either
  way (not an access escalation), but availability of the emergency path is most of what break-glass is for.
  Fixed as one mechanism change, not two guard patches: the list/get read path
  (`ListBreakGlassActivations`/`GetBreakGlassActivation`) no longer persists a wall-clock transition at all —
  `State` is now a genuine read-time projection, watermark-clamped by reusing #1651's `rbacEffectiveNow`
  mechanism (the treatment #1653's own issue body suggested). The one place a TTL-lapse transition is ever
  persisted moved to `ReconcileExpiredBreakGlassActivation`, called only from `ActivateBreakGlass` (a mutating
  operation) immediately before its own INSERT. `RevokeBreakGlass`'s guard (and its proxy mirror) now depend only
  on whether the row has already been explicitly revoked. The durable guard this establishes — the one a future
  change would break — is asserted directly:
  `TestBreakGlassReads_NeverPersistState` proves neither read function ever writes. Every changed behavior was
  verified by mutation (revert the fix, confirm the specific test goes red) before landing. #1653 reopened on
  GitHub with the full account, not closed with a note — its premise was falsified, not refined.

## Governing ADRs

ADR-084 (admin-bypass structural marker, implemented 2026-09-02), ADR-087 (RemoteStorage deletion pass),
ADR-088 (system proxy layer design), ADR-091 (machine `CreatedBy` attribution classification), ADR-092 (audit
event `UserID` for a machine principal), ADR-093 (remote `--by`-authority check), ADR-094 (time handling: UTC
internally, wall-clock distrust), ADR-095 (database path resolution), ADR-096 (anti-enumeration, 403-for-both),
ADR-097 (schema-epoch downgrade guard).
