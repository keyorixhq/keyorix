# ADR-088: What the `/system` proxy layer is for — narrow-primitive delegation, not full-operation delegation

## Status

**Accepted (2026-08-28).** Wave 2 design pass. Investigation and this ADR
only — no production code changes in this pass.

Renumbered from ADR-087 to ADR-088 during review: that number was already
taken by `docs/adr-087-remote-storage-deletion-pass.md` (landed in #1583).
Two ADRs sharing a number is the same species of defect as everything else
this document is about — an identifier that does not identify. See
`scripts/check-adr-numbers.sh` (added alongside this fix) for the guard.

## Summary

The working label for Wave 2 was "hub-side authorization." Tracing the six
issues that motivated it shows they are not one problem:

- **(a) Authority evaluated where the data isn't** — #1575. Resolved by
  ADR-086 as "the CLI sends the operation, the hub decides." This ADR
  specifies the mechanism.
- **(b) Proxies reimplement core operations instead of delegating to it** —
  #1546, #1551, #1572, and the general shape underlying every fix this
  campaign has made to `server/http/handlers/*_proxy.go`.
- **(c) Two isolated validation gaps** — #1579, #1580. Not architectural.
  Explicitly out of scope for this ADR; fix separately, whenever.

**The question this ADR answers:** should a `/system` proxy be a thin
transport shim over `internal/core`, never a parallel implementation?

**Answer: not in the form asked.** A mechanical classification of all 55
`/system` proxy handlers that currently perform a write-shaped raw storage
call found that **full delegation to the matching `internal/core` operation
is the wrong fix in 52 of 55 cases** — not because delegation is a bad
instinct, but because the existing `internal/core` operations are the wrong
grain. They bundle side effects (audit writes, role grants, cascades,
notifications) that a relay endpoint must NOT repeat, because those side
effects already happened once, on the spoke that originated the operation.
Calling the full core method a second time on the hub would duplicate them.

The rule this ADR adopts instead: **a `/system` proxy that mutates state
must call a narrow, purpose-built, exported `internal/core` primitive for
its authorization/precondition check, and may perform its own raw,
conditional (CAS-shaped) write for the persistence step.** This is not a
new pattern — it is the shape every real fix this campaign has already
landed (`RequireAuthorityForRole` in #1578/#1582, `GuardLastAdminDeactivation`
in #1572's partial fix, `IsValidMachineTransition` in the machine-identity
transition fix). This ADR names it, measures its cost, and proposes
enforcing it going forward.

## Context: how the count was derived

`server/http/raw_storage_bypass_guard_test.go`'s own detection logic
(`exportedCoreStorageWrappers` + `handlerStorageCalls`) was reused directly
(via a temporary, uncommitted test) rather than re-implemented, and scoped
to the 172 distinct handler functions registered under `/system`
(`server/http/router.go:1097-2023`, confirmed by direct enumeration — every
one of the 172 route registrations maps to a distinct handler, all named
`*Proxy`).

- **172** total `/system` proxy handlers.
- **117** make no write-shaped raw storage call at all — either pure reads
  (`Get*`/`List*`/`Count*`/`Export*`, mechanically excluded: a read confers
  no new access, so there is no ceiling to bypass) or already delegate to
  `internal/core` for their mutation. Out of scope for the delegation
  question — there is nothing to delegate.
- **55** make at least one write-shaped raw storage call. This is the real
  population for "should this proxy delegate," not the "34" figure named in
  the brief. I could not reconstruct where 34 came from and did not try to
  force my count to match it — this number is mechanically reproducible
  (rerun `TestWave2ScratchClassifyProxies`, described below, against current
  `origin/main`) and is what the rest of this ADR is built on.

### Classifying the 55

| Bucket | Count | What it means |
|---|---|---|
| Delegable as-is | 1 | `DeleteEnvironmentProxy` — the one true 1:1 passthrough with zero side effects on either side. |
| Delegable with a signature change | 48 | A real `internal/core` operation exists, but its signature/side-effects don't fit a relay endpoint's contract. See below. |
| No core equivalent — real architectural constraint | 5 | `AcquireSchedulerLockProxy`/`ReleaseSchedulerLockProxy` (pure distributed-lock infrastructure, no authorization dimension to delegate), `DeleteMFAStepUpGrantsForProxy` (capability-reducing, no ceiling), plus 2 below. |
| No core equivalent — because core deliberately refuses the *unsafe* shape the proxy uses | 3 | Live findings, not architecture notes. See below. |

**48, not "most are delegable as-is."** The dominant reason (~39 of 48) is
not a missing field on the wire — it's that the matching `internal/core`
operation always performs additional writes a relay endpoint's contract
explicitly must not repeat: `TransitionMembership` unconditionally runs
role-grant writes + audit + notifications; `UpdateUser` re-derives the whole
row from a fresh read and re-diffs it, losing the `FromActive` CAS
precondition the wire needs; `CreateSetupToken`/`IssueMachineToken`/
`BeginWebAuthnRegistration` all need a plaintext secret to hash themselves,
and the wire, by design, never carries one. A smaller cluster (9 of 48 —
the MFA enrollment family and the retention-purge family) was invisible to
the mechanical scanner entirely: their real `internal/core` wrapper
(`ActivateMFA`/`DisableMFA`/`RegenerateMFARecoveryCodes` in `mfa.go`,
`PurgeExpiredSoftDeletes` in `purge.go`) calls the storage method through a
`tx` handle inside a `WithTransaction` closure, a call shape the guard's
`exportedCoreStorageWrappers` doesn't follow (it recognizes `c.storage.X()`
and one-hop unexported-sibling calls, not `tx.X()`). This is the same
"an enumeration is only as complete as the idioms it knows" lesson Wave 1
already applied to the stub-completeness guard (#1576) — recorded here as a
guard gap worth the same treatment, not fixed in this pass.

**The 3 live findings, surfaced by asking "why does no core equivalent
exist" instead of assuming the absence is neutral:**

1. **`UpdateMachineIdentityProxy`** performs a raw full-row `Save` (its own
   comment says so, `machine_identities_proxy.go:402`). `internal/core`'s
   own comment three files over (`machine_identities.go:168-172`) explains
   *why* no core method offers this shape: "the actual write goes through
   `TransitionMachineIdentityState`, a conditional `WHERE id = ? AND state =
   ?` persist, rather than a plain `UpdateMachineIdentity` — because
   `RemoteStorage.WithTransaction` is a no-op passthrough over HTTP... a
   plain Lock-then-Update proxy pair would silently lose the #388 guarantee
   entirely under remote mode." `UpdateMachineIdentityProxy` is exactly that
   plain Lock-then-Update proxy pair. It reproduces, over HTTP, the race
   `internal/core` was deliberately rewritten to avoid.
2. **`UpdateMembershipProxy`** is worse — no lock-then-read step at all, a
   blind write of the wire's own body. The doc comment on the *adjacent*
   handler in the same file names it directly: `TransitionMembershipProxy`
   "persists the membership's full row via a single conditional UPDATE...
   so a concurrent transition on the same membership can't be silently
   reverted... **the way `UpdateMembershipProxy` could**"
   (`project_memberships_proxy.go:210-214`). This is a self-documented,
   currently-live race between two routes in the same file, unresolved.
3. **`CreateSecretDependencyProxy`** calls the raw, non-exclusive
   `CreateSecretDependency`. `internal/core/secret_dependencies.go`'s own
   comment explains `CreateSecretDependencyExclusive` was built specifically
   to replace "this method orchestrating a `ListSecretDependenciesForProjectForUpdate`
   read and a separate `CreateSecretDependency` call" (#260) — a cycle-check
   TOCTOU. A safe `CreateSecretDependencyExclusiveProxy` already exists
   (`secret_dependencies_proxy.go:163`) at a *different* route. The unsafe
   route sits right next to it, still reachable.

These three are filed as new issues (verdict, not fix — this pass is
investigation-only): **#1585, #1586, #1587** (see report). They are the
concrete proof that "no core equivalent" is not automatically a safe
classification — it is exactly the question this ADR's enforcement
mechanism (below) is designed to force someone to answer, instead of a
proxy silently reaching for raw storage because it was the shortest path to
green.

## What the proxy layer actually is

The three findings above are not three independent oversights — they share
a shape. `UpdateMachineIdentityProxy` reproduces, over HTTP, the exact race
`TransitionMachineIdentityState` was rewritten to close. `UpdateMembershipProxy`
races the adjacent, already-fixed `TransitionMembershipProxy` — the
adjacent handler's own doc comment names the bug it reproduces. `CreateSecretDependencyProxy`
calls the pre-#260 unsafe primitive while the safe
`CreateSecretDependencyExclusive` route sits beside it in the same file,
unused. In each case, `internal/core` was rewritten at some point to fix a
race or correctness bug, and the proxy calling into storage directly was
never updated to match — it is still calling the shape that existed
*before* the fix.

That makes the `/system` proxy layer, in aggregate, **a set of stale forks
of `internal/core`, each frozen at whatever revision existed when it was
written.** A proxy doesn't rot the usual way, by going unmaintained — it
rots by `internal/core` moving on without it.

That reframing turns three findings into a bounded, mechanical sweep rather
than a guess: **for every `internal/core` primitive that was rewritten to
fix a race or correctness bug — #518, #G42, #260, and whatever else the
commit history surfaces — check whether the corresponding `/system` proxy
carries the fix.** That list is derivable from history (find each
primitive's own fix commit, diff it against its current proxy caller), not
from re-auditing all 55 handlers from scratch. This is framed here and
filed as **#1592**; it is explicitly **not run in this pass** — Wave 2's
scope is investigation and rule-setting, not the sweep itself. #1592 is
itself sequenced behind the guard blind-spot fixes below, for the same
reason: a sweep run against an incomplete guard reopens the exact blind
spot that let #1585/#1586/#1587 go unnoticed.

## Costing the rule against #1546, #1551, #1572

For each, what does delegation look like versus the existing/available
bolt-on (narrow-primitive) fix:

**#1546 — `TransitionMembershipProxy`.** Bolt-on: call
`RequireAuthorityForRole(ctx, actorID, m.ProjectID, m.Role)` before the
existing conditional CAS write, mirroring the #1578/#1582 fix to the
sibling `CreateMembershipProxy`/`UpdateMembershipProxy` — the primitive
already exists, ~5 lines. Full delegation to `core.TransitionMembership`
would additionally run `AddProjectMember`/`RemoveProjectMember` (role-grant
writes) on the hub — #1546's own open question is whether the spoke already
relayed that role-grant change via a *separate* proxy call
(`AssignRoleWithExpiryProxy`/`RemoveAllProjectRoleGrantsProxy`, both fixed
under #1542). If it did, full delegation double-applies the grant change.
Delegation doesn't resolve #1546's open question — it adds a new
duplication risk on top of it. Bolt-on wins outright.

**#1572 — `UpdateUserIfActiveStateMatchesProxy`.** The last-admin half was
already bolted on (`GuardLastAdminDeactivation`). The remaining gap — PAT
revocation and session deletion don't fire — has a bolt-on fix that's now
*cheap*: `RevokeAllPersonalAccessTokensForUserProxy` and
`DeleteSessionsForUserExceptProxy` already exist as safe, delegating routes
(both are in the 117 "no raw write" bucket). The fix is calling those same
two already-safe `internal/core` operations directly, in sequence, after
the CAS write succeeds and the transition is `true→false` — no new
primitive needed. Full delegation to `core.UpdateUser` would instead
re-derive the whole row from a fresh `GetUser` read and re-diff every
field, *losing* the `FromActive` CAS precondition this route exists to
provide — actively worse than the bolt-on, not just more code.

**#1551 — `RevokeMachineIdentityCredentialProxy`.** This one genuinely
needs a wire change (a `project_id`/scope field, both client and server) —
the issue's own filed text already says so. But delegation to
`core.RevokeMachineToken` needs the *identical* field, plus duplicates the
calling node's own audit event (per the classification above). The correct
shape is: add the scope field to the wire, add a narrow ownership-check
primitive (extracted from `RevokeMachineToken`'s `machineInProject` check,
newly exported), call that before the existing raw revoke. Same wire cost
as delegation, less duplicated-audit risk.

**All three: bolt-on (narrow primitive + raw conditional write) beats full
delegation.** Not on convenience — on correctness. Full delegation risks
duplicating side effects the spoke already applied once. This generalizes:
of the 55, only 1 is a true passthrough; the other 54 all have *some*
reason a relay endpoint's contract differs from the full operation's, and
in every fixed case so far, the fix that shipped was narrow-primitive
extraction, never full delegation. The user-stated hypothesis — "a `/system`
proxy should be a thin transport shim over `internal/core`, never a
parallel implementation" — is disproven in its literal form. The corrected
form — a `/system` proxy performs its own conditional write, but must not
skip an authorization/precondition check `internal/core` already knows how
to make — is what the evidence supports, and is cheaper than either
alternative (see Decision).

## #1575 under the rule

Confirmed by reading `internal/cli/user/user.go`: the CLI is not making
HTTP calls to human-facing endpoints for these commands. It embeds
`internal/core.KeyorixCore` directly and calls its methods
(`SuspendUser`/`DeleteUser`/etc.) as in-process Go calls. Under
`storage.type: remote`, that `KeyorixCore`'s storage backend is
`RemoteStorage`, so those methods' own storage calls go out over HTTP to
the exact `/system` proxy endpoints this ADR is about. The CLI *is* a spoke
in this topology, same as any server-to-server caller.

`requireUserAuthority`'s own doc comment confirms why the local check
exists at all: "`None of the KeyorixCore methods these commands call
(SuspendUser, ReactivateUser, DeleteUser, etc.) check permissions
themselves (the HTTP handler's job is done by router middleware)`" — in
embedded/local mode, there's no HTTP layer for the bare CLI process at all,
so nothing enforces authorization unless the CLI does it itself, which is
why `requireUserAuthority` was correctly added. Under remote mode, that
same gap exists, but the fix is not "make the client-side check work
against remote data" (ADR-086 already rejected this) — it's routing the
check to where the data already lives.

**Confirmed wire gap:** `RemoteStorage.UpdateUserIfActiveStateMatches(ctx,
user *models.User, fromActive bool)` (`remote_users.go:412`) carries no
actor identity at all — only the target row and the CAS precondition. The
hub-side proxy has no way to know *who* is asking beyond the transport
credential that authenticated the HTTP connection. To let the hub decide
whether the resolved `--by` actor specifically holds authority, the wire
needs a new field carrying that actor's ID, and the proxy needs the same
narrow-primitive check `requireUserAuthority` runs today, moved server-side.

**This is not the fat-client pattern ADR-086 rejected.** ADR-086 forbade
shipping *permission data* to the client so it could compute authorization
itself. Carrying an actor *identity claim* on the wire and having the hub
independently verify that identity's authority against the hub's own data
is the same shape every other authenticated request already uses — the
client asserts who it's acting as, the server decides if that's allowed.

**Under the rule: does the CLI still call `core.Authorize` at all?** No,
under `storage.type: remote` specifically — `requireUserAuthority`/
`requireInviteAuthority` become no-ops (or are skipped) for that storage
type, and the hub's `/system` proxy refuses via its own narrow
authorization primitive, surfaced to the CLI as the existing user-facing
error. Under embedded/local mode, nothing changes — `core.Authorize` keeps
working exactly as today, because the data is local. Two of the four
`requireInviteAuthority`-gated commands (`invite send`, via
`CreateInvitationProxy`) are **already structurally fixed** by Wave 1's
`RequireAuthorityForRole` addition — for those, the remaining work is
purely client-side (stop calling the doomed local check under remote mode)
plus confirming `actorID(r)` on the hub side resolves to the right identity
for a CLI-originated call, not just an HTTP-session-originated one. The
account-lifecycle family (`user suspend/reactivate/delete/revoke-sessions/
resend-setup-link`, `migrate user-to-machine`) has no server-side check to
route to yet — `UpdateUserIfActiveStateMatchesProxy` was already found
above to have no such primitive — so that half is genuinely new work, not
a client-side flip.

**Command where hub-side deciding genuinely cannot work: none found.**
Every one of the 11 operations is something the hub already decides
authoritatively for every other topology (HTTP-session, node-credential,
spoke-server) that reaches it. The CLI-direct-embedding topology is the
only one that currently tries to decide locally, and only because it
predates `RemoteStorage` entirely. I looked for a case where the
authorizing fact is something only the CLI's local process context knows —
found none; `--by` is always resolved to a plain user ID before the check
runs, and the hub can resolve and check that ID exactly as well as the CLI
can, using data the CLI structurally cannot have per ADR-086.

## Decision

**Adopt the rule, guard it for new/touched handlers, convert retroactively
only where a finding exists.** Same ratchet shape used everywhere else in
this campaign (C5, the stub-completeness guard, the raw-storage-bypass
guard itself).

**The rule, precisely:** a `/system` proxy handler that performs a
write-shaped storage call must either (a) have no independent ceiling to
bypass (documented, same as today's `rawStorageBypassAllowlist` reasons:
read-shaped, no-independent-ceiling, or a stated architectural exception),
or (b) call an exported `internal/core` primitive — existing or newly
extracted — that performs the authorization/precondition check the
equivalent human-facing operation performs, before its own raw conditional
write. Full delegation to a high-grain `internal/core` operation is
correct only when that operation is already a true 1:1 passthrough (rare —
1 of 55 measured).

## Precondition this rule depends on

This rule is not a general law about proxy architecture. It holds only
under the current split of responsibility between the CLI and the hub:
**the CLI executes `internal/core`, and the hub receives the resulting
writes as separate proxy calls.** That split is *why* full delegation is
wrong — the side effects a full-grain `internal/core` operation would run
have already run once, on the spoke that originated the call. A relay
endpoint replaying the same operation duplicates them.

If operation ownership moves to the hub instead — the CLI sends an intent,
the hub executes `internal/core` itself, the direction ADR-086's own
resolution of #1575 already points — the double-execution problem this
rule exists to prevent disappears, because there is no longer a second
execution to duplicate against. **This rule is void the moment that
happens, and must be re-derived, not inherited.** This is the ADR-083 →
ADR-085 lesson applied prospectively: a superseding architectural decision
invalidates the reasoning built on top of it, and the only protection
available at decision time is writing the dependency down before it's
forgotten.

**Alternatives considered and rejected:**

1. **Full retroactive refactor of all 55 (or "34").** Rejected by the
   evidence itself: 48 of 55 need a *new or modified* `internal/core`
   primitive, not a swap of an existing call. That's real design work per
   handler (what does the narrow primitive look like, what does it NOT
   repeat), not a mechanical pass. A blanket refactor would either take
   weeks or get rubber-stamped to reach green — exactly the outcome this
   campaign's own standing practice warns against.
2. **An unenforced convention.** Rejected: this campaign's own history is
   the counter-evidence. The raw-storage-bypass pattern this ADR responds
   to *is* an unenforced convention that drifted for months before #1542's
   guard caught it structurally. A convention with no guard is worth
   nothing the moment someone is under time pressure to ship.
3. **ADR-086's ship-role-IDs-over-the-wire.** Already rejected there for
   #1575; reaffirmed here as also wrong for (b) — it would make the CLIENT
   decide permissions using fetched data, the fat-client pattern this whole
   campaign has been closing off. Not reconsidered.
4. **The reviewer's original "34 handlers" figure.** Not reproducible from
   the codebase or its commit history; superseded here by the mechanically
   derived, rerunnable count of 55. Recorded by name rather than left to
   quietly disappear, since a number nobody can trace becomes a trap for
   whoever next tries to reconcile a different count against it.
5. **The reviewer's original hypothesis — "a `/system` proxy should be a
   thin transport shim over `internal/core`, never a parallel
   implementation."** Rejected on correctness grounds, not cost: it did not
   account for `internal/core` operations bundling side effects (audit
   writes, role grants, cascades, notifications) that already ran once on
   the spoke that originated the call. Full delegation would duplicate them
   on the hub. See "Costing the rule" above for the three concrete cases
   this was tested against and lost.

**Enforcement:** extend `server/http/raw_storage_bypass_guard_test.go`'s
existing shape rather than build a parallel mechanism. Today's guard
already flags exactly this condition (write-shaped raw call + matching
core wrapper exists) for the 41 (40 measured + `DeleteEnvironmentProxy`,
already-flagged) cases where a wrapper is visible to it, and requires a
reasoned `rawStorageBypassAllowlist`/`knownUnfixedRawStorageBypasses`
entry. Two changes close the loop:

- Fix the `tx.X()` blind spot found above (9 handlers currently invisible
  because their real wrapper calls through a transaction handle) — same
  "population must be structurally complete" standard Wave 1 already
  applied to #1576. Not done in this pass; filed as a finding.
- The three real "no core equivalent" gaps found above are not a guard
  problem — they're `internal/core` doing exactly the right thing (refusing
  to offer an unsafe primitive). The proxies that went around that refusal
  are the bug. No new guard shape needed; #1585/#1586/#1587 are ordinary
  fixes once someone picks them up.

No new AST guard needs to be built from scratch — the existing one already
encodes "flag a write-shaped raw call, require a reasoned entry," which is
this rule's enforcement mechanism. What's missing is closing its two blind
spots (tx-handle calls, and the fact that "no wrapper" isn't automatically
safe), not a new mechanism.

**This rule is not enforced until both blind spots close.** A guard that
misses 9 real wrappers because they're called through `tx.X()`, and that
treats "no wrapper visible" as "no ceiling to bypass," is exactly the guard
shape that let the three live findings above go unnoticed. Until both are
fixed, "the guard didn't flag it" does not mean "safe" — it may mean
"invisible to the guard." Recording a rule the guard cannot yet see is the
same failure this campaign has spent a month cataloguing: a check that
can't fail on the case it exists for is worth nothing.

**Sequence, in order:**

1. Close the guard's two blind spots (`tx.X()` call-shape recognition; stop
   treating "no wrapper found" as an automatic pass).
2. Only then does rule enforcement start counting: new or touched handlers
   must satisfy the rule or carry a reasoned allowlist entry.
3. Retroactive conversion of already-existing handlers happens only where a
   finding forces the question (as #1546/#1551/#1572 and #1585/#1586/#1587
   already have) — never as a scheduled sweep.

## Out of scope for this ADR

- **#1579, #1580** — isolated validation gaps, not architectural. Fix
  separately.
- **Retroactive conversion of the 54 non-passthrough handlers.** This ADR
  establishes the rule and where it applies; it does not schedule the
  conversion. Per the ratchet: convert when a finding forces the question
  (as #1546/#1551/#1572 already have), not as a scheduled sweep.
- **The 9-handler `tx.X()` guard blind spot and the 3 live findings**
  (#1585/#1586/#1587) — filed, not fixed here.
- **The mechanical stale-fork sweep (#1592)** — framed above, filed, not
  run here; sequenced behind the guard blind-spot fixes.
- **Fixing #1546/#1551/#1572 themselves** — costed above, not implemented;
  a later pass, scoped by this ADR.

## Consequences

**Positive.** The rule is evidence-backed, not asserted: it explains why
every real fix this campaign has shipped took the narrow-primitive shape
without anyone having named it as a rule before now. It gives #1575 a
concrete mechanism (hub-side check via the same primitive shape, actor
identity on the wire) rather than a restatement of "hub-side" as an
unexplained goal. It surfaced three live, previously-unknown findings by
asking "why" instead of accepting an absence as neutral.

**Negative.** 48 of 55 still need bespoke design work, one handler at a
time, each requiring a judgment call about what a narrow primitive should
and shouldn't repeat from its full-grain sibling. This is slower than a
mechanical rule would have been, and this ADR does not make that slowness
go away — it explains why the alternative (mechanical full delegation)
would have been actively wrong, not just slower.
