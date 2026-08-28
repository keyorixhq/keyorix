# ADR-087: RemoteStorage deletion pass — from a verified-dead subset to a fully classified surface

## Status

**Accepted (2026-08-28), extended (2026-08-28).** Two passes, same ADR
(updated in place per the standing instruction to correct rather than
fork a document when the correction is to its own completeness claim, not
its conclusions):

- **Part 1** executed the deletion Wave 0 (`docs/g80-wave0-remote-storage-partition.md`)
  sized but explicitly held — "nothing gets deleted this pass," Wave 0c —
  pending review of its corrected partition: #1511's 13 methods, individually
  re-verified and deleted. At the time, 158 of 171 structurally-stub methods
  had never been examined for reachability at all — stated explicitly below,
  not hidden.
- **Part 2** (this update) closes that gap: all 158 classified LIVE / DEAD /
  UNRESOLVED, 4 LIVE-and-stubbed findings filed (#1589, not fixed), 154
  confirmed-DEAD methods deleted, and a permanent guard
  (`TestEveryStructuralStubHasReachabilityVerdict`) added so a new stub-shaped
  method can no longer join the registry without a verdict. See "Part 2" below.

**The surface is now fully classified.** Of the 183 currently-registered
`RemoteStorage` stub methods: 7 LIVE (kept, 3 per ADR-086 + 4 from Part 2, all
either correct-by-design or filed as findings), 169 DEAD (12 already deleted
by an earlier round via #1583's 13-method set minus `GetSecretVersion`'s full
removal, 154 deleted by Part 2 — see "Part 2: the deletion" below for the
precise count), 7 UNRESOLVED (Wave 0's original residue, still untouched —
unresolved means kept, not "probably fine"). Zero remain unclassified.

## What this is, precisely

Wave 0 partitioned `RemoteStorage`'s stub/wire-call surface, believed at the
time to be 88 stub-shaped methods (75 already-classified `remoteUnsupported()`
stubs + 13 raw `fmt.Errorf` stubs). Wave 1 (#1576) replaced regex-based stub
detection with AST-structural reachability and found the true population is
**171**. That correction does two different things, and conflating them is
the mistake this ADR exists to avoid:

- **It does not, by itself, invalidate any individual DEAD verdict.** A
  larger denominator doesn't make a correctly-classified DEAD method live —
  DEAD-ness is a property of the method's own call graph, not of how many
  siblings exist. Every DEAD verdict this pass acts on was re-traced against
  current `origin/main` (post-#1576, post-#1582), not carried forward
  unverified from Wave 0's original evidence — see "Re-verification, and one
  correction" below.
- **It does invalidate the completeness claim.** Wave 0's own partition work
  (Task 1 of its doc) individually examined and classified exactly **13**
  methods — the 13 raw stubs, before #1576 existed. The other 158 of the
  171 (149 marked `statusIntentional`, 22 marked `statusUnverified` in
  `remote_unsupported_completeness_test.go`'s `remoteUnsupportedAllowlist`)
  were classified by other processes — ~10 prior campaign rounds for the
  original 75, and #1576's widening pass for the other 96 — never by Wave
  0's LIVE/DEAD/UNRESOLVED lens specifically. **158 of 171 structurally-stub
  `RemoteStorage` methods have never been examined for deletion-worthiness
  at all.** They are correctly classified as legitimate, permanent-or-
  provisional stubs (the guard is green); whether any of them could instead
  be *deleted* — narrowing `storage.Storage`'s interface, or simplifying a
  method body — is a question nobody has asked yet, not one that's been
  asked and answered "no."

**This pass removes a verified-dead subset. It does not remove "the dead
RemoteStorage surface," and does not claim to.** The 158 unexamined methods
are out of scope for this pass and are not touched.

## The criterion

A `RemoteStorage` method is DEAD (safe to delete its wire-call body) if,
tracing every caller transitively from `internal/core` through to the CLI,
HTTP handlers, and gRPC services on current `origin/main`:

1. Every CLI entry point that could reach it is either (a) guarded by one of
   the three established remote/local dual-path idioms —
   `common.NewRemoteClient()` / `common.NewRemoteClientWithCredentials()` /
   `common.ResolveRemote()` / `common.IsClientMode()` (the complete,
   campaign-derived idiom set — see Wave 0's own "Task 1 (Wave 0c)" section
   for how completeness was established, correcting an earlier miss where
   `run.go`'s direct `ResolveRemote()` call wasn't yet known as a fourth
   idiom shape) — which diverts to a raw-HTTP passthrough that never
   constructs a `RemoteStorage`-backed core at all, taking precedence over
   the wire call in every complete `storage.type: remote` configuration; OR
   (b) itself blocked by a separate, independently-verified barrier (see
   `AssignRole`/`RemoveRole` below for the one case where this applies); and
2. Every non-CLI caller (HTTP handler, gRPC service, server-boot path) is
   confirmed server-only — never constructed against a `RemoteStorage`-backed
   core (ADR-083: `validateRemoteStorageNotServer` rejects that topology at
   config-validation time, unconditionally); and
3. The corresponding `server/http/router.go` route does not exist at all —
   confirmed by direct read, not inferred from the wire call's own success —
   so even a caller that reached this method would get a 404/405 on every
   real attempt, never real behavior.

This is exactly `TestRemoteStorageWireCalls_HaveMatchingRoute`'s own
structural definition of "missing route," combined with Wave 0's own
call-chain tracing discipline, re-applied to current source.

## Re-verification, and one correction

All 13 of issue #1511's orphaned wire-call methods were re-traced against
current `origin/main` (post-#1576/#1581, post-#1582) before this pass acted
on any of them. All 13 confirmed DEAD. One correction to Wave 0's own stated
evidence surfaced during re-verification:

**`AssignRole`/`RemoveRole`.** Wave 0's doc cites each as "DEAD-in-practice
(guarded)," listing only their `NewRemoteClient()`-guarded CLI call sites
(`rbac/assign_role.go`, `rbac/remove_role.go`, plus `user/create.go` for
`AssignRole`). Re-tracing found a caller Wave 0's evidence never examined:
`internal/cli/request/review.go` — on the campaign's own 22-file "unguarded"
list, but never checked against these two specific methods — reaches
`core.finalizeAccessRequestApproval` → `AssignUserRole`/`RemoveUserRole` →
`storage.AssignRole`/`RemoveRole`, with **no** `NewRemoteClient`-family guard
anywhere in the chain.

The corrected picture is not "Wave 0 was wrong that these are dead" — they
are dead, confirmed — but the REASON is different and, on inspection,
stronger: `request review`'s path is blocked by **two independent barriers**
on the same permanently-stubbed RBAC primitive chain
(`GetUserRoleIDsAt`/`GetUserGroupRoleIDsAt`/`RoleSetHasPermission`, which
ADR-086 keeps stubbed by design, not as a temporary gap) —
`requireReviewAuthority`'s own `Authorize` call at the CLI entrypoint, AND
`core.ApproveAccessRequestWithExpiry`'s own `requireAuthorityForRole` call
inside `internal/core` itself. Neither depends on a `NewRemoteClient()`-style
guard at all. Both fail closed today, and both rest on a stub chain ADR-086
commits to keeping permanently — this is more durable evidence than the
guarded-CLI-path shape Wave 0 originally cited, not less. Recorded here so a
future reader doesn't inherit "guarded by NewRemoteClient()" as this pair's
reason when it never was.

While re-deriving the CLI guard-idiom file list against current source (the
same derivation Wave 0c performed), two files not on Wave 0's original
22-file list were found: `secret/delete.go` and `secret/versions.go`. Both
traced to completion; neither reaches any of the 13 methods in this pass's
deletion set. No verdict changed as a result.

## What was NOT deleted, and why

**Three of Wave 0's originally-sized "raw stub" deletion candidates required
no action.** Wave 0 sized `CreatePermission`, `CreateProject`, and
`CreateEnvironment` (plus `AssignPermissionToRole`, see below) as ~3-4
additional deletions alongside #1511's 13. Re-checking current source: all
three are *already* bare `fmt.Errorf("not supported in remote storage")`
stubs with no wire-call body ever present to remove, and all three are
already registered in `remoteUnsupportedAllowlist` as `statusIntentional`
(Wave 1's #1576 widening absorbed and correctly classified them before this
pass started). There is nothing left to delete for these three — Wave 0's
sizing predates #1576's registry existing at all. This pass's actual
deletion set is **13 methods**, not 16-17: #1511's full list, and nothing
else.

**Kept, per ADR-086 (LIVE — do not delete, do not implement over the
wire):**

- `GetUserRoleIDsAt`
- `GetUserGroupRoleIDsAt`
- `RoleSetHasPermission`

Reached directly by `core.Authorize` (bypassing any HTTP/gRPC middleware
entirely), called by 11 CLI commands under `storage.type: remote` (#1575).
Deliberately kept stubbed — implementing them over the wire would have the
CLI fetch role/permission data and decide authorization client-side, the
fat-client anti-pattern this campaign has dismantled elsewhere. The correct
fix is hub-side authorization, deferred to Wave 2 (unifies #1546, #1551,
#1572, #1575).

**Kept, UNRESOLVED (evidence gap named, not resolved — kept means kept, not
"probably fine"):**

- `IsProjectMember` — evidence leans DEAD-in-practice; both plausible call
  chains sit behind a `NewRemoteClient()` guard (#1512, closed on this
  verdict, Wave 0c).
- `IsGroupProjectScoped` — same shape and citation as `IsProjectMember`.
- `GetUserRoleIDsExact` — reached from `internal/core/project_members.go`
  (add/remove project member); no CLI caller found in the time available;
  not confirmed HTTP-only either.
- `GetUserRoleScopes` — evidence leans LIVE via the Keyorix Connect CLI
  subtree (`internal/cli/connect`); not fully traced.
- `GetMachineRoleScopes` — mirrors `GetUserRoleScopes`; same Connect-subtree
  gap.
- `GetUserGroupPermissions` — reached from SoD conflict detection
  (`internal/core/sod.go`) and `rbac_management.go`; not traced to a CLI
  entry point.
- `AssignPermissionToRole` — evidence leans DEAD (reached only from
  `server/http`/`server/grpc` handlers plus boot-time-only
  bootstrap/reconcile callers; no CLI caller found), but not individually
  re-verified to the same depth as the 13 methods this pass acts on — stays
  UNRESOLVED, not promoted to DEAD, on that basis alone.

None of these seven were touched. Closing any of them requires either a
live-mode integration test (the `NewRemoteClient()`-guard-absent edge case
Wave 0's own doc names as unresolved) or a deeper Connect-subtree trace —
Wave 2 or a dedicated follow-up, not this pass.

## The deletion

13 `RemoteStorage` methods across `internal/storage/store/` (8 files:
`remote_secrets.go`, `remote_auth.go`, `remote_rbac.go`,
`remote_risk_exceptions.go`, `remote_sharing.go`, `remote_stats.go`), each
converted from a live-but-permanently-404ing `rs.client.<Verb>(...)` call to
`remoteUnsupported("MethodName")` — the same pattern the other 158
classified stubs already use — except `GetSecretVersion`, which is not
declared in the `storage.Storage` interface at all (an orphan method on the
concrete `*RemoteStorage` type; `core.GetSecretVersion` calls the plural
`GetSecretVersions` instead, never this one) and so was removed entirely,
not stubbed:

`CreateSecretVersion`, `CleanupExpiredSessions`, `AssignRole`, `RemoveRole`,
`UpdateRiskException`, `CreateShareRecord`, `GetShareRecord`, `GetStats`,
`GetSecretVersion` (fully removed), `GetLatestSecretVersion`,
`IncrementSecretReadCount`, `ListSharedSecrets`, `CheckSharePermission`.

Each now has a `remoteUnsupportedAllowlist` entry
(`remote_deletion_pass_completeness_test.go`) citing its individual DEAD
evidence, and `remote_wire_route_coverage_test.go`'s `knownMissingRoutes` —
the map that tracked all 13 as "confirmed missing route" — is now empty; a
future genuinely-new gap gets a fresh entry there, triaged the same way, not
by resurrecting these.

This is a method-body deletion, not an interface change (per Wave 0's own
framing): `storage.Storage` is unchanged for all 12 stubbed methods.
`GetSecretVersion` is the one exception, and it was never part of the
interface to begin with, so nothing there changed either. **No interface
narrowing was performed or is proposed by this pass** — the 158 never-
examined methods, and whether `LocalStorage`'s side of any of them is also
dead, remain a separate, larger, unstarted investigation.

**Findability.** Tag `pre-remote-topology-deletion`, annotated, at the
commit immediately before the first removal (mirrors `g80-pre-remediation`'s
own convention) — `git show pre-remote-topology-deletion:<path>` retrieves
any of these 13 methods' original wire-call bodies. The deletion commit
enumerates all 13 by name.

## #1511 final accounting

Issue #1511's body lists exactly these 13 wire calls and no others (confirmed
by reading the issue directly, not assumed from this document). The split:

| Category | Count | Methods |
|---|---|---|
| Closed by this deletion (stub conversion) | 11 | `CreateSecretVersion`, `CleanupExpiredSessions`, `AssignRole`, `RemoveRole`, `CreateShareRecord`, `GetShareRecord`, `GetStats`, `GetLatestSecretVersion`, `IncrementSecretReadCount`, `ListSharedSecrets`, `CheckSharePermission` |
| Closed by this deletion (outright removal, not in the interface) | 1 | `GetSecretVersion` |
| Stale — already fixed in a prior round, this pass closes the remaining client-side half | 1 | `UpdateRiskException` (server route deliberately removed in a prior G79 round; the client's dead wire call, the actual #1511 defect, is what this pass converts to a stub) |
| Closed by a NEW route/fix | 0 | — |
| Still open | 0 | — |

**13 of 13 resolved. Issue #1511 closes with this pass**, cited by the
deletion commit and this ADR — not left open with residue, since none
remains.

## A finding surfaced, not fixed, during re-verification

Un-skipping `server/http/remote_storage_risk_exceptions_test.go`'s two
`t.Skip()`-quarantined tests (to confirm `UpdateRiskException`'s fix
actually resolves what they were skipped for) surfaced a **second,
previously-invisible blocker**, unrelated to #1511: both tests' harness
authenticates as a machine/node credential
(`createNodeToken`), and `CreateRiskExceptionProxy` requires a human
principal ("only a human principal may create a risk exception"). This
predates this pass — the original `t.Skip()` short-circuited before the
`Create` call ever ran, so it was never actually observed. Both tests were
re-skipped with an updated, accurate reason (the original #1511/#G79 cause
no longer applies; this second one does) rather than fixed — out of scope
for a dead-wire-call deletion pass. Flagged for its own follow-up.

## The invariant, not just the list (#1578/#1582)

`core.RequireAuthorityForRole` now protects three handlers —
`CreateInvitationProxy`, `CreateMembershipProxy`, `UpdateMembershipProxy` —
each found by a different method, one at a time. A guard now asserts the
invariant directly: `server/http/role_grant_authority_guard_test.go`'s
`TestEveryDirectRoleGrantChecksAuthority` flags any `/system` handler that
persists a Role-shaped field directly via storage without calling
`RequireAuthorityForRole`. Verified red (against a deliberately-reintroduced
gap in `CreateMembershipProxy`) and green (all three intact).

## Part 2: the remaining 158, fully classified

Classification is the deliverable of Part 2; deletion is a byproduct. The
population is 158 structurally-stub `RemoteStorage` methods — every one of
the 171 (post-#1576) minus Wave 0's 13 raw stubs and #1583's 12 — that had
never been examined for reachability at all. Unclassified dead code becomes
live code without re-review: this codebase has a concrete instance
(`RequireNodeCredentialOrPermission`'s node arm sat with no caller until
someone asked whether it could have one, and answering took a full
investigation and an ADR, ADR-085). The prize is the LIVE ones, not the DEAD
ones — #1575 found 11 CLI commands broken under `storage.type: remote`
because they reach hard stubs, and that sweep exercised *commands*, not
*methods*, so more #1575-class breaks could hide in an unexamined 158.

### The criterion, mechanized

Wave 0's partition was done by hand-tracing plus grep, and its own
idiom-completeness miss (`ResolveRemote()`, corrected in Wave 0c) is exactly
the failure mode a 158-method manual pass would reproduce at scale. Instead,
`scripts/analysis/remote_storage_classify.go` (a standalone, `go:build
ignore` analysis script — not a CI guard, run once for this pass) computes
the same criterion mechanically:

1. **Reverse reachability.** Every `(c *KeyorixCore)` method's body is parsed
   (`internal/core/*.go`), and for each, the full transitive closure of
   `storage.Storage` methods it can reach — through any chain of same-receiver
   sibling calls, AND through a `storage.Storage`-typed closure parameter
   (the `c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
   tx.Method(...) })` shape used throughout this package) — is computed,
   memoized, cycle-safe. An earlier version of this tool missed the closure
   shape entirely, which would have silently undercounted reachability for
   every core method using `WithTransaction`; caught by a spot-check (see
   "Two real gaps the tool itself had" below) and fixed before any verdict
   was finalized.
2. For each target storage method, every **exported** core method reaching it
   (only exported methods are callable from outside `internal/core`) is
   listed, then cross-referenced against `internal/cli` (does an unguarded
   file reference it?), and against the **whole** `server/` tree — not just
   `server/http/handlers`/`server/grpc/services`/`server/main.go`, which an
   earlier version of the scan checked and which missed
   `server/middleware/auth.go` and `server/grpc/interceptors/auth.go`
   entirely (also caught and fixed — see below).
3. A method with at least one unguarded CLI reference is `CANDIDATE-LIVE` —
   a candidate, not a verdict. Every one of the 12 candidates the tool
   produced was individually hand-verified (see "Ten candidates, four real"
   below) before being called LIVE or reclassified DEAD; the tool narrows,
   it does not decide.
4. A method with zero exported-core-method reach gets a repo-wide plain-text
   safety-net scan (outside `internal/storage/store` and the interface
   declaration) before being called `DEAD-NO-CORE-CALLER` — this tool only
   follows `*KeyorixCore`-receiver methods, and a storage call reached
   through some OTHER helper type `KeyorixCore` constructs and hands off to
   (confirmed real: `core.AnomalyDetector` holds its own `.storage` field,
   unrelated to any `*KeyorixCore` receiver) would otherwise be invisible to
   it. The safety net demoted 5 of the original 9 `DEAD-NO-CORE-CALLER`
   results to `UNRESOLVED` for hand-tracing; all 5 resolved DEAD by hand
   (see below), none flipped LIVE.

### Two real gaps the tool itself had, both caught before finalizing

Sanity-spot-checking the mechanical output — not trusting it blind, per the
standing instruction that a manual pass is where the Wave 0 idiom error came
from, which cuts the same way against trusting an unaudited *automated* pass
too — found two real gaps in the classifier itself, both fixed and the full
158-method run repeated before any verdict was finalized:

- **The `WithTransaction`-closure blind spot** (above). Found by direct
  grep after the tool reported `DeleteAuditLogsBefore`/`CreateAnomalyAlert`
  as `DEAD-NO-CORE-CALLER` when a targeted grep found a real caller
  (`tx.DeleteAuditLogsBefore(...)` inside a `WithTransaction` closure). Fixing
  it changed 2 verdicts from `DEAD-NO-CORE-CALLER` to correctly-resolved DEAD
  without manual tracing, and surfaced 2 NEW genuine reachable paths
  (`ListPersonalAccessTokensByUser`, `SetAccountState` — both later resolved
  DEAD by hand, see below) that the tool had wrongly called `DEAD-SERVER-ONLY`
  before the fix.
- **The narrow server-side scan.** Found when `GetPersonalAccessTokenByHash`
  et al. reported `UNRESOLVED` despite obviously being consumed by
  authentication middleware. Broadening the scan from three named
  directories to the whole `server/` tree resolved all 3 affected methods to
  `DEAD-SERVER-ONLY` correctly.

### Ten candidates, four real

The classifier flagged 12 `CANDIDATE-LIVE` methods (after the two fixes
above). Each was individually traced by hand — reading the actual CLI command
code, not trusting the tool's text-match — because "a Go call-graph edge is
not a deployment path" cuts against automation exactly as much as it cuts
against a human skim:

- **3 were tool false positives.** `GetSecretAccessSchedule`,
  `TryIncrementSecretReadCount`, `TryIncrementSecretNodeReadCount` all
  matched `internal/cli/secret/source_aws.go`'s `api.GetSecretValue(...)` —
  the AWS SDK's OWN `secretsmanager.Client` method, unrelated to
  `core.KeyorixCore.GetSecretValue`, sharing only a name. Confirmed by
  checking `source_aws.go`'s receiver type directly. Every genuine caller of
  `core.GetSecretValue` (`secret/get.go`, `run/run.go`) is guarded.
- **5 are DEAD via the SAME barrier `AssignRole`/`RemoveRole` were corrected
  to (Part 1, above) — not a `NewRemoteClient()`-family guard, but a
  fail-closed authority check that itself depends on the permanently-stubbed
  RBAC chain (ADR-086):**
  - `CreateRejectionReasonTemplate`, `DeleteRejectionReasonTemplate`,
    `ListRejectionReasonTemplates` — `request rejection-templates
    add/delete/list` all call `requireTemplateAuthority` (→ `Authorize` →
    `GetUserRoleIDsAt`) before ever reaching these methods.
  - `ListPersonalAccessTokensByUser`, `SetAccountState` — every unguarded
    path reaching them (`migrate user-to-machine`, `user
    reactivate/force-password-reset/suspend`) is blocked by
    `requireUserAuthority`'s identical `Authorize` call first.
  - This is the fourth+fifth+sixth+seventh+eighth confirmed instance of this
    specific barrier shape in this campaign (after `AssignRole`/`RemoveRole`
    in Part 1) — strong evidence the barrier is systemic, not coincidental:
    any core action gated by a CLI `--by`-authority check
    (`requireReviewAuthority`/`requireTemplateAuthority`/`requireUserAuthority`,
    all sharing the `Authorize(ctx, actorID, permission, scope)` → stubbed
    `GetUserRoleIDsAt` shape) is dead under `storage.type: remote` today,
    durably, because ADR-086 keeps that chain stubbed by design.
- **4 are genuinely LIVE** — see "LIVE-and-stubbed findings" below.

### LIVE-and-stubbed findings (filed as #1589, not fixed)

Per the standing instruction (verdict before fix; do not fix a LIVE-and-
stubbed method in this pass — several may dissolve if Wave 2 adopts a
proxy-delegation design, and fixing piecemeal now risks building something
that pass discards), all 4 are filed in
[#1589](https://github.com/keyorixhq/keyorix/issues/1589) with full evidence,
summarized here:

| Method | Command | Fails | Severity |
|---|---|---|---|
| `CreateNotification` | `request access` / `request secret-access` | **OPEN** — `notifyWithSeverity` swallows the error; the request succeeds, the approver is silently never notified | Most serious: silently wrong, not a clean refusal. Not a security bypass (no unauthorized access granted), but a documented side effect silently drops with zero signal. Affects every notification-worthy core action under remote mode, not just these two entry points. |
| `ListAccessRequestsByIDs` | `request bulk-approve` / `bulk-reject` | Closed — the stub error propagates cleanly (`ListAccessRequestsByIDs` is called before any per-item processing) | Real, currently-broken feature — same class as #1575 — but a clean refusal. |
| `ListSessionTokenHashesForUser` | `user update --active=false` | Closed / verified safe — error discarded (best-effort cache eviction only); `server/middleware/auth.go`'s `serveAuthCacheHit` independently re-checks `AccountStillUsable` on every warm-cache hit regardless | Low severity — a deactivated user is still blocked on their very next request either way; already reasoned through in `internal/core/users.go`'s own doc comment. |
| `WithTransaction` | Same `user update --active=false` path | Closed / verified safe for this one confirmed use — no real cross-call atomicity, but the deactivation branch's own doc comment already reasons through exactly this remote-mode scenario | Standing architectural limitation (no server process, no real HTTP-spanning transaction, ever) rather than a fix target — worth recording because a FUTURE unguarded caller using `WithTransaction` less carefully would not automatically be safe. |

The LIVE-and-stubbed count (4) is not large enough to warrant stopping before
the deletion pass per the standing instruction — proceeding to deletion in
the same pass.

### Part 2: the deletion

154 methods (158 minus the 4 LIVE above) converted from whatever non-network-
reaching body they had — a real removed feature's leftover logic, a bespoke
`fmt.Errorf` message, or in several cases a **silent no-op** (`return nil` /
`return nil, nil` with NO error at all — e.g. `SaveStatsSnapshot`,
`TouchSession`, `TouchPersonalAccessToken`, `AddPasswordHistory`,
`RecentPasswordHashes`, `PrunePasswordHistory` all previously claimed success
while doing nothing) — to the canonical `remoteUnsupported("MethodName")`
stub, mechanically via `scripts/analysis/remote_storage_stub_rewrite.go` (an
AST-precise surgical rewriter: replaces only each target method's parameter
names, blanked to `_`, and body byte range; zero-values each non-error return
position by inspecting its own type text — pointer/slice/map/interface →
`nil`, `bool` → `false`, `string` → `""`, numeric → `0`; everything else in
each file — doc comments, unrelated functions, formatting — untouched).
Confirmed safe for every silent-no-op case specifically BECAUSE each is
independently confirmed DEAD (no live caller today), so a caller-visible
behavior change from "silently reports success" to "clean explicit error"
has zero effect on any currently-running deployment.

Full per-method list, criterion, and evidence: `git show
pre-remote-topology-deletion-158:internal/storage/store/` for the pre-rewrite
bodies (tag below), and
`internal/storage/store/remote_deletion_pass_completeness_test.go`'s
`addRemoteUnsupported` entries (Part 1's 13) plus
`remote_reachability_registry_test.go`'s 154 corresponding entries (Part 2)
for the individual reasoning — not restated in full here (154 one-line
citations would dwarf this document without adding information beyond what
the machine-checked registry already carries and enforces).

**Findability.** Tag `pre-remote-topology-deletion-158`, annotated, at the
commit immediately before Part 2's first removal — same convention as Part
1's `pre-remote-topology-deletion` tag. The deletion commit enumerates all
154 by name.

### Kept: the UNRESOLVED residue (unchanged — Wave 0's original 7)

Part 2 classified all 158 it examined; none resolved LIVE or DEAD required
demoting to UNRESOLVED (the 5 `DEAD-NO-CORE-CALLER`→`UNRESOLVED` safety-net
hits above all resolved DEAD by hand). The UNRESOLVED set is still exactly
Wave 0's original 7, listed in "What was NOT deleted, and why" above:
`IsProjectMember`, `IsGroupProjectScoped`, `GetUserRoleIDsExact`,
`GetUserRoleScopes`, `GetMachineRoleScopes`, `GetUserGroupPermissions`,
`AssignPermissionToRole`. Kept means kept — closing any of these still
requires either a live-mode integration test or a deeper Connect-subtree
trace, Wave 2 or a dedicated follow-up, not this pass.

### Task 4: staying classified

`internal/storage/store/remote_reachability_registry_test.go` adds
`remoteReachabilityRegistry` — a registry deliberately SEPARATE from
`remoteUnsupportedAllowlist` (adding a field to that struct would touch
~183 existing call sites across ~20 files for a concern those entries were
never about) — and `TestEveryStructuralStubHasReachabilityVerdict`: every
method `actualRemoteUnsupportedStubs` finds must have a
`reachabilityLive`/`reachabilityDead`/`reachabilityUnresolved` entry, no
third state, no silent additions — same shape as
`TestRemoteUnsupportedStubsAreAllowlisted` and as
`scripts/ci-test-legs.sh`'s C5 ratchet. Verified red (a temporarily-removed
entry) and green (restored). All 183 currently-registered methods have an
entry as of this pass — the guard is satisfiable today and enforces the
invariant going forward: a new stub-shaped method can no longer join the
registry without a reachability verdict.

### Guard population: predicted vs. actual

`remoteUnsupportedAllowlist`/`actualRemoteUnsupportedStubs`: 183 before Part
2 → 183 after (Part 2 reclassifies existing structural stubs; it does not
create new ones — every one of the 154 rewritten methods was ALREADY
structurally a stub, by the same "never reaches `rs.client`" definition,
before this pass touched it). Predicted 183, actual 183, exact match.

`remoteReachabilityRegistry`/`TestEveryStructuralStubHasReachabilityVerdict`:
0 before Part 2 (registry did not exist) → 183 after. Predicted 183 (7 LIVE +
169 DEAD + 7 UNRESOLVED), actual 183, exact match.

## Guardrail check: does anything here overturn ADR-083/ADR-086?

No, for both parts. ADR-083's server-topology gate is unaffected throughout
— nothing in either part touches `validateRemoteStorageNotServer` or the
route-registration/proxy-tier cleanup ADR-083 defers; Part 2's criterion
explicitly relies on it (current source confirmed unconditional before
either part's classification work began). ADR-086's three-method keep-list
is unaffected and re-confirmed in both parts. Part 1's `AssignRole`/
`RemoveRole` correction, and Part 2's five further instances of the identical
barrier shape, both strengthen rather than contradict ADR-086's premise that
the RBAC stub chain is a durable, by-design barrier — Part 2 finds it gating
FIVE more call paths ADR-086's own investigation didn't examine, all still
correctly blocked.
