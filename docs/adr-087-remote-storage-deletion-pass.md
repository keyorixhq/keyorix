# ADR-087: RemoteStorage deletion pass — a verified-dead subset, not a sweep

## Status

**Accepted (2026-08-28).** Executes the deletion Wave 0
(`docs/g80-wave0-remote-storage-partition.md`) sized but explicitly held —
"nothing gets deleted this pass," Wave 0c — pending review of its corrected
partition. This ADR is that review, plus the deletion itself.

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

## Guardrail check: does anything here overturn ADR-083/ADR-086?

No. ADR-083's server-topology gate is unaffected — nothing in this pass
touches `validateRemoteStorageNotServer` or the route-registration/proxy-
tier cleanup ADR-083 defers. ADR-086's three-method keep-list is unaffected
and explicitly re-confirmed above. The `AssignRole`/`RemoveRole` correction
strengthens, rather than contradicts, ADR-086's premise that the RBAC stub
chain is a durable, by-design barrier — it's now confirmed to gate a SECOND
call path ADR-086's own investigation didn't examine.
