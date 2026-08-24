# G80 Phase 0 remediation notes

Internal record of the G80 finding and its Phase 0 fix — not customer-facing (no
production deployments exist; see the Severity correction below for why no security
advisory is warranted). This is the durable record of how the bug class was closed,
referenced from the wire-DTO code comment (`internal/storage/store/remote_secrets.go`).

## The bug

`storage.Storage.UpdateSecret` is implemented by both `LocalStorage` (a full GORM
`Save(secret)` — every field persists) and `RemoteStorage` (a narrow wire DTO). Before
this fix, `RemoteStorage`'s wire DTO (`secretUpdateWireRequest`) carried only `MaxReads`,
`Expiration`, and `ClearExpiration` — 3 of `models.SecretNode`'s ~28 persisted fields.
Any other field a caller mutated before calling `storage.UpdateSecret` was silently
dropped: the call returned success, but the hub's authoritative row was untouched.

## Call-site inventory (exhaustive, verified against the full working tree)

| File:line | Function | Field(s) mutated |
|---|---|---|
| `internal/core/secrets.go:297` | `UpdateSecret` (`applyUpdateSecretFields`) | `Type`, `Metadata`, `MaxReads`, `Expiration`/clear, (Phase 0 adds `Description`) |
| `internal/core/secrets.go:421` | `RotateSecret` (called via `RotateSecretOnDemand`) | `LastRotatedAt`, `UpdatedAt` |
| `internal/core/classification.go:86` | `ClassifySecret` | `Classification` |
| `internal/core/secret_ownership.go:89` | `TransferSecretOwnership` (public wrapper) / `transferOwnership` (shared primitive, also used by `ReassignOwnedSecrets`) | `OwnerID` |
| `internal/core/secret_move.go:94` | `MoveSecret` | `ParentID` |
| `internal/core/secret_bulk_rename.go:154` | `BulkRenameSecrets` | `Name` |
| `internal/core/secret_description.go:66` | `SetSecretDescription` | `Description` |
| `internal/core/rotation_executor.go:699` | `SetSecretAutoRotate` | `AutoRotate`, `RotationLength`, `RotationCharset`, `RotationBackend`, `RotationRef` |
| `internal/core/secret_extend_expiring.go:56` | `ExtendExpiringSecrets` | `Expiration` (already covered by the original 3-field DTO) |

No call site outside `internal/core` calls `storage.UpdateSecret` directly.

## Field classification

Every persisted field on `models.SecretNode` is classified in `updateSecretAllowlist`
(`server/http/handlers/secret_update_diff.go`) into one of three buckets:

- **Allowed** (plain `secrets.write`, no further gate): `Type`, `Description`,
  `MaxReads`, `Expiration`, `Metadata`.
- **Ignored** (hub-computed, client value never inspected): `UpdatedAt`.
- **Rejected** (server-owned, or gated by a check this endpoint cannot run):
  everything else — `ID`, `ProjectID`, `EnvironmentID`, `Name`, `IsSecret`,
  `ReadCount`, `Classification`, `Status`, `CreatedBy`, `OwnerID`, `IsShared`,
  `CreatedAt`, `LastRotatedAt`, `AutoRotate`, `RotationLength`, `RotationCharset`,
  `RotationBackend`, `RotationRef`, `CertNotAfter`, `DeletedAt`,
  `RetentionOverrideDays`, `ParentID`.

`LastRotatedAt` deserves a specific note: it looks like `UpdatedAt` (hub-computed,
client value shouldn't matter) but is deliberately classified **rejected**, not
ignored. `RotateSecret` leaves it unchanged on a byte-identical resubmission (#408 —
stamping it would falsely signal "recently rotated, low risk" for material that never
changed) and sets it to now on a real rotation. A generic field diff cannot distinguish
those two cases, and unconditionally stamping `now()` on any update through this
endpoint (e.g. a plain `Description` edit) would wrongly mark an unrelated secret as
just-rotated — reintroducing #408's exact failure mode. Recording a rotation needs its
own dedicated endpoint (tracked as follow-up work below), not a slot in the generic
allowlist.

## Audit-trail divergence (a distinct, more severe finding)

Every one of the five gated `internal/core` operations wrote its audit event
**unconditionally after `storage.UpdateSecret` returned a nil error**, with no check
that the field had actually persisted:

- `classification.go:91` — `LogSecretUpdatedWithDiff` with a before/after classification
  diff
- `secret_ownership.go:97` — `EventSecretOwnerTransferred`, including `{FromUserID,
  ToUserID}` in the audit detail
- `secret_move.go:104` — `EventSecretMoved`
- `secret_bulk_rename.go:158` — `LogSecretUpdatedWithDiff`, plus `report.Outcomes`
  marking the item `renamed`
- `rotation_executor.go:713` — `EventSecretAutoRotateConfig`, including
  rotation-backend binding details

Before this fix, in any code path that reached these functions through
`RemoteStorage`, the audit log would have recorded these changes as genuinely
happened — a classification downgrade, an ownership transfer, a rotation-backend
binding — when the hub's authoritative row was untouched. This is an affirmatively
false record, not merely a silent gap, and would have been the more serious finding of
the two had any of these operations been live-reachable (see below).

Phase 0 fixes this **as a structural consequence**, not via a separate code change:
every one of the five functions already checked `storage.UpdateSecret`'s error and
returned before writing its audit event. Making the write fail loudly (instead of
returning a false success) makes the existing `if err != nil { return }` guard do the
right thing automatically. `TestG80Phase0_ClassifySecret_RejectedInConnectedMode` and
`TestG80Phase0_SetSecretAutoRotate_RejectedInConnectedMode`
(`server/http/remote_storage_g80_secret_update_test.go`) assert this explicitly: a
rejected operation writes zero new audit events, for the two operations that can be
driven end-to-end (see the severity correction for why not all five could be).

## Severity correction

The original investigation (this document's own Step 1) characterized the bug as live:
"ownership transfers, moves, renames, classification changes, description edits and
rotation-backend bindings all return success to the operator while changing nothing on
the hub's authoritative row" in CLI connected mode. **This overstated live
exploitability.**

Tracing every real CLI command for the five gated operations found that **none of them
reach these `internal/core` functions via `RemoteStorage` at all.** `classify.go`,
`move.go`, `bulk_rename.go`, `reassign_owner.go`, `autorotate.go`, and `description.go`
(`internal/cli/secret/`) each check `common.NewRemoteClient()` first and, when
connected, make their own direct REST call (e.g. `PATCH /secrets/{id}/classification`)
— a code path entirely separate from `core.KeyorixCore` + `storage.Storage`.
`classify.go` has no embedded-mode fallback at all. A repo-wide search for real callers
of the five gated `internal/core` functions turns up only server-side HTTP/gRPC
handlers, which per ADR-083 (accepted) can never run against `RemoteStorage` (a server
cannot boot with `storage.type: remote`).

So the five gated operations were never reachable via `RemoteStorage.UpdateSecret` by
any code path that exists today. The only genuinely live path was
`internal/cli/secret/update.go`'s embedded-mode fallback (`storage.type: remote`
configured directly, no `keyorix connect`) — `core.UpdateSecret` →
`Type`/`MaxReads`/`Expiration`/`Metadata` (Phase 0 adds `Description`).

This does not make the fix unnecessary: `storage.Storage` is a documented interface
contract two implementations must both honor (ADR-083 explicitly preserves
`storage.type: remote` as "the CLI's actual, working use case"), and any current or
future caller constructing a `RemoteStorage`-backed core — a new CLI command, a script
embedding `internal/core` as a library, `examples/secret_crud/main.go`-style usage —
would hit the same class of bug. The `TestG80Phase0_ClassifySecret_*` /
`TestG80Phase0_SetSecretAutoRotate_*` end-to-end tests are deliberately framed as
guarding the contract for **future** callers, not as reproducing a live incident.

**Process lesson**: the original sweep enumerated call sites (every place a field is
mutated before `storage.UpdateSecret`) but never traced whether any of those call
sites is reachable from a real CLI entrypoint against `RemoteStorage`. Call-site
enumeration and reachability analysis are different questions — closing a bug class
requires both. Reachability analysis is now mandatory for findings in this campaign,
not just call-site enumeration.

## Two further pre-existing bugs surfaced while testing (separately tracked, not fixed here)

- **[#1511](https://github.com/keyorixhq/keyorix/issues/1511)** — 13 confirmed
  `RemoteStorage` wire calls have no matching `router.go` route at all (discovered via
  `CreateSecretVersion`, which meant on-demand rotation's value-persistence step fails
  with a hard 405 in connected mode, before ever reaching the `LastRotatedAt`
  question). Guarded going forward by
  `internal/storage/store/remote_wire_route_coverage_test.go`.
- **[#1512](https://github.com/keyorixhq/keyorix/issues/1512)** — ADR-083's
  `RemoteStorage.IsProjectMember` stub (`"not supported in remote storage"`) blocks
  `internal/core.CheckSecretPermission`'s owner fast-path, so even a secret's own owner
  cannot call `SetSecretDescription`, `TransferSecretOwnership`, or any other
  `EnforceSecretWritePermission`-gated function against a `RemoteStorage`-backed core.
  This is why `TransferSecretOwnership`, `MoveSecret`, `BulkRenameSecrets`, and
  `SetSecretDescription` could not be driven end-to-end in this fix's test suite —
  unrelated to G80, not fixed here.

## Follow-up work (not implemented in Phase 0)

One PR per gated operation, each with its own narrow `RemoteStorage` proxy method,
wire request, and dedicated hub endpoint that calls the same `internal/core` function
server-side so the authorization checks (SoD, `requireAdminAuthorityAt`, the G09
read-approval gate) run authoritatively at the hub — mirroring the existing
`TransitionSecretStatus` precedent. Suggested order, by how dangerously the current
silent no-op fails open (now moot for live risk per the severity correction above, but
still the right order for closing the latent/structural gap):

1. Classification (`ClassifySecret`)
2. Rotation config / backend binding (`SetSecretAutoRotate`) — and recording a
   rotation timestamp (`LastRotatedAt`), the same endpoint family
3. Ownership transfer (`TransferSecretOwnership`)
4. Move (`MoveSecret`)
5. Description (`SetSecretDescription`) — lowest priority; folding it into the generic
   allowlist (already done in Phase 0) may be sufficient permanently, since it has no
   authorization gate beyond plain `secrets.write`
6. Rename — research first whether a single-secret rename path exists outside
   `BulkRenameSecrets` before designing its wire shape

## G-series CI-triage campaign (C0–C5)

A separate, later effort against the same root problem class this document's "process
lesson" describes: a mechanism that handles a subset and stays silent about the rest.
This time the subset was CI coverage itself — three packages excluded from the go test
matrix since 2026-04-27 (`internal/core$`, `internal/cli$`, `server/http$`, plus
`internal/storage/remote`), one test's mock mismatch, and nobody watching for four
months. Living record of what's been found and fixed; update the relevant section as
each PR lands rather than appending a new one per PR.

### C0 / C0b — measuring the blind spot

`internal/core` (322 test files, dollar-anchored exclusion — `internal/core/storage` was
separately pinned into CI all along and never actually dark): **0 failures.** The
original excluding test, `TestListSecretsWithSharingInfo`
(`internal/core/sharing_indicators_test.go:176`), was rewritten by #1048 (2026-07-19,
ACL-grant surfacing) three months before this audit — verified directly with
`-run '^TestListSecretsWithSharingInfo$' -v`, not inferred from a clean package run. The
exclusion outlived the failure it was created for by about a month with nothing
surfacing that.

`internal/cli$` (dollar-anchored — only the 6-file top-level package was ever dark; the
~300 files under `internal/cli/...` have been in CI and green throughout, pinned across
`root-1/2/3`) and `internal/storage/remote` (4 files): both **0 failures.**

`server/http` (91 test files): **18 failures, 8 root causes**, triaged below.

### #1520 — re-enable `internal/core` in CI

First attempt folded `internal/core` into `root-4`'s catch-all leg: went red on the real
runner (605.014s against the leg's 600s budget) despite passing locally (369.6s,
`-race`, isolated). Fix: a dedicated `core` leg with a deliberately generous 1800s
timeout — a per-package timeout exists to catch hangs, not police a speed budget; tuning
to just past an observed duration risks the same intermittent-red outcome that let the
original exclusion look justified in hindsight.

**Isolating the leg did not measurably help**: 624.821s isolated vs. 605.014s contended.
If leg-level contention with other test binaries were the dominant cause, isolation
should have shown a real improvement — it didn't. The more likely explanation is that
GitHub's `ubuntu-latest` 2-core hosted runner is simply slower than the local
development machine for this race-heavy workload (~1.7x), independent of what else
shares the leg. **Record the cause as runner speed, not contention, in any future
writeup** — the contention narrative was the working hypothesis before this number, and
should not survive past it.

Follow-up, not urgent: #1523 (split the 323-test-file `internal/core` package — the
underlying symptom this timing problem is a symptom of).

### server/http — 18 failures, 8 root causes (triaged, C1–C4 below)

| Root cause | Tests | Disposition |
|---|---|---|
| Last-admin driver-token fixture (see C1 below) | 2 | C1 — fixture rebuilt |
| bcrypt fixture is 61 chars, `isPlausibleBcryptHash` requires 60 | 3 | C2 fix |
| CSV header assertion predates G25's added columns | 1 | C2 fix |
| Secret-dependency fixture uses nonexistent IDs 501/502 | 3 | C2 fix |
| `buildActiveSetupToken` never sets `SubjectUserID` | 5 | C2 fix |
| `UpdateRiskExceptionProxy` deliberately unregistered (#G79, tracked in #1511) | 2 | C3 quarantine |
| `RevokeRiskExceptionProxy`/`ApproveRiskExceptionProxy` proxy the core policy function instead of the raw conditional primitive, so a lost race/already-decided precondition returns a 500 instead of `matched=false` (#1531) — **corrected**; originally misdiagnosed as another actorID(r)==0 instance, see the recurring-pattern section below | 2 | C3 quarantine |

### C1 — the last-global-admin invariant (fixed as a fixture bug, not a product bug)

**The invariant was never actually tested**, not stale. `createRBACDriverToken`
(removed; formerly `server/http/remote_storage_rbac_role_grants_test.go:33-57`) granted
its driver identity the `system_admin` role "purely to authenticate" the downstream
call. The server-side guard doesn't trust a wire-supplied admin-role set —
`RemoveGlobalAdminRoleGuardedProxy` (`server/http/handlers/rbac_role_grants_proxy.go:351`)
resolves its own list via `resolveInstallAdminRoleIDsProxy`, from
`breakGlassContainmentAdminRoleNames` (`server/http/handlers/break_glass_proxy.go:125`) —
`{"super_admin", "admin", "system_admin"}`, deliberately broadened by #G79 specifically
to stop a caller from undercounting admins via an incomplete wire-supplied set. So the
driver was itself a standing second admin from the moment it was created, in both
affected tests, before either test's first assertion ran. The code (guard, role-name
list) is correct; the test fixture was wrong.

Fix: swap the driver's authentication to `createNodeToken`
(`server/http/integration_test.go:109-130`, an existing helper already used by ~16 other
tests in this package) — a node-type machine credential, `ActorTypeMachine` with
`MachineIdentityType: core.MachineTypeNode`, never assigned any role. Verified at the
storage-query level, not inferred: `ListGlobalAdminAssignmentsForUpdate`
(`internal/storage/store/local_rbac.go:371-413`), which `RemoveGlobalAdminRoleGuarded`
calls to decide whether an admin survives, queries only `models.UserRole` and
`models.GroupRole` rows — no machine-identity table is referenced anywhere in that path,
so a node credential is structurally invisible to this guard regardless of what (if
anything) it might separately hold.

Shipped as three tests, not two: the original refusal test (now genuinely exercising a
single-admin state), a new standalone
`..._SucceedsWithSurvivingAdmin_RealServer` test (two real admins from the start,
assert removal succeeds — without it, a guard that always errored would still pass the
refusal test), and the existing concurrent-race test with an added explicit
"at least one global admin remains" assertion (`ListGlobalAdminAssignmentsForUpdate`'s
full result, not just the userA/userB-specific count already there).

Verified all three catch a broken guard, not just that they pass: temporarily forced the
guard to never refuse (both single-admin and concurrent-race tests correctly went red)
and separately forced it to always refuse (the new success test correctly went red).
Reverted both before this PR.

Separately investigated (out of scope for C1, not fixed): whether
`RequireNodeCredentialOrPermission`'s node-credential arm (`server/http/router.go:1069,1089`)
over-reaches elsewhere in the same `/system` route group. It does —
`AssignRoleWithExpiryProxy`/`AssignRoleToGroupWithExpiryProxy`
(`server/http/handlers/rbac_role_grants_proxy.go:97-135`) let a bare node credential
grant any role, including admin-tier ones, to any user or group, with no ceiling check
and no audit-log write on that path. Filed as #1524; not touched here.

### Standing practice: verify a repaired fixture by breaking its subject

Established while fixing C1 and confirmed again on every C2 fixture repair: after
rebuilding a test's fixture so it stops failing, temporarily break the actual invariant
the test claims to cover (comment out a guard's refusal branch, force a check to always
pass, etc.) and confirm the test goes red. Revert before committing. A green test after
a fixture fix proves the fixture compiles and runs; it does not prove the test still
reaches and exercises its subject — that's exactly the failure mode C2's four root
causes were (twelve tests failing during setup, before ever touching the cycle
detection / duplicate rejection / setup-token logic they claim to cover). This is now
the default verification step for any fixture repair in this campaign, not optional
due diligence — every C1 and C2 fix in this document was verified this way before being
reported as fixed.

### Task 3 — runner headroom audit

Pulled every `test-suite` leg's actual `go test`-only elapsed time (step start to its
last package's `ok` line, NOT the job's total wall-clock, which includes ~1-2 min of
checkout/setup overhead that doesn't count against `-timeout`) from PR #1520's completed
CI run, against the OLD 600s/1800s budgets:

| Leg | Timeout (old) | Actual | Headroom | |
|---|---|---|---|---|
| root-1 | 600s | 461s | 139s (23%) | |
| root-2 | 600s | 504s | 96s (16%) | |
| root-3 | 600s | 555s | 45s (7.5%) | ⚠️ tight |
| root-4 | 600s | 569s | 31s (5.2%) | ⚠️⚠️ tighter than internal/core died at (605s) |
| core | 1800s | 625s | 1175s (65%) | comfortable |
| handlers-1 | 600s | 465s | 135s (22.5%) | |
| handlers-2 | 600s | 497s | 103s (17%) | |
| handlers-3 | 600s | 409s | 191s (32%) | |
| handlers-4 | 600s | 465s | 135s (22.5%) | |

**Finding: 600s was miscalibrated repo-wide, not just for `internal/core`.** root-3 and
root-4 were already sitting in the same danger zone `internal/core` crossed —
`internal/core` was just the first leg to actually cross the line, not an outlier. Fixed
in #1526 (raises every leg to 1800s, standalone PR, landed ahead of C4).

**server/http CI-duration prediction for C4**: local baseline (this machine, `-race
-timeout 1200s`, all C2/C3 fixture fixes applied, the 2 known-separate C1-scope failures
excluded) — see the PR that lands C4 for the actual measured number and the leg timeout
it was sized from. Applying the ~1.7x local→CI runner factor established above
(`internal/core`: local 369.6s → CI 624.8s isolated) to that local number is the
starting point for C4's dedicated leg's timeout, with generous headroom on top per the
same reasoning as every other leg in this document — a hang detector, not a speed
budget. **C4 must pin server/http to its own dedicated leg, not fold it into root-4's
catch-all** — root_base() is the catch-all computation, so un-excluding server/http
without pinning it would drop 91 HTTP integration test files into root-4 (already at
569s/5.2% headroom before #1526's fix) — a guaranteed timeout, not a surprise.

**Refreshed after #1526 + C4** (job wall-clock — includes ~1-2 min checkout/setup
overhead, NOT the go-test-only elapsed time the table above uses; both are against
the CURRENT 1800s budget, same for every leg):

| Leg | Wall-clock | % of 1800s budget |
|---|---|---|
| root-1 | 8m27s (507s) | 28% |
| root-2 | 7m36s (456s) | 25% |
| root-3 | 9m21s (561s) | 31% |
| root-4 | 9m34s (574s) | 32% |
| core | 12m53s (773s) | 43% |
| handlers-1 | 8m10s (490s) | 27% |
| handlers-2 | 8m6s (486s) | 27% |
| handlers-3 | 7m9s (429s) | 24% |
| handlers-4 | 8m17s (497s) | 28% |
| http-1 | 11m54s (714s) | 40% |
| http-2 | 11m2s (662s) | 37% |
| http-3 | 11m18s (678s) | 38% |
| http-4 | 11m34s (694s) | 39% |
| http-5 | 11m36s (696s) | 39% |
| http-6 | 12m4s (724s) | 40% |

Every leg now sits comfortably under budget (max 43%, `core`) — no leg in the
5-7.5%-headroom danger zone #1526 was written to fix. `http-1..6` landed within
predicted range (~30% target, measured 37-40% — job wall-clock includes overhead
the prediction's go-test-only estimate didn't, accounting for the gap).

### A recurring pattern: node-credential auth vs. `actorID(r)`-gated authority checks

Three separate instances found in this campaign so far, all the same shape: a
`server/http/handlers/*_proxy.go` route that (correctly, per #G79) re-validates
authority server-side against `actorID(r)` — the authenticated caller of THIS
specific request — rather than trusting a wire-supplied value. `actorID(r)`
(`server/http/handlers/catalog.go:19`) returns `0` for a node-credential-authenticated
caller, since `middleware.GetUserFromContext` only recognizes a real user session.
Node credentials are this package's dominant test-harness pattern (`createNodeToken`,
used in ~20+ real-server test files) because most proxies in this tree are pure
storage passthroughs with no such check — but the handful that DO check authority
structurally cannot pass for a node-credential caller, and the failure surfaces as
whatever the specific test's fixture bug looked like, not as an obviously-related
symptom:

1. **C1** — `RemoveGlobalAdminRoleGuardedProxy`: `createRBACDriverToken`'s driver
   held `system_admin`, masking the actorID(0) problem behind a DIFFERENT bug (the
   driver counting as an extra admin) for the RBAC guard specifically.
2. **C2** — `CreateUserWithRoleGrantsProxy`'s `ValidateRoleGrantAuthority(ctx,
   actorID(r), grants)`: masked behind the bcrypt-length bug for
   `TestRemoteStorageCreateUserWithRoleGrants_RealServer`/
   `_ConcurrentDuplicateEmailRace_RealServer` — fixing the bcrypt fixture alone
   surfaced this as a NEW 403, not a pass. Unlike C1's case, this one DOES have a
   clean fixture fix: a real admin session (`createTestToken`) legitimately has the
   authority these grants need, so swapping just these two tests' caller identity
   (not the harness default, which stays `createNodeToken` for every other test in
   the file) resolves it correctly rather than requiring quarantine.

**Correction (post-C3): the risk-exception revoke/approve quarantines are NOT a
third instance of this pattern.** Originally attributed to actorID(0) directly
(same shape as C1/C2). Directly disproven by unskipping both tests and running
them: the real cause is a wire-contract mismatch (`RevokeRiskExceptionProxy`/
`ApproveRiskExceptionProxy` proxy `core.KeyorixCore.RevokeRiskException`/
`ApproveRiskException` — the POLICY functions, which turn a lost race or an
already-decided precondition into a Go error — instead of the raw
`RevokeRiskExceptionIfNotRevoked`/`ApproveRiskExceptionIfPending` conditional
primitives `putConditionalTransition`'s wire contract expects), filed separately
as #1531 and unrelated to node-credential identity. The lesson generalizes past
this specific case: **a plausible-sounding cause matching an already-established
pattern is not verified until the test has actually been run with the fix/cause
applied** — pattern-matching a new failure against a known shape is a hypothesis,
not a diagnosis.

The actorID(r) pattern itself is real and was swept exhaustively (not just
found by accident) after C2: every `actorID(r)` call site in
`server/http/handlers` (18 sites) was graded on what happens when it resolves to
0 — hard-fail (safe), silently skip, accidentally match a sentinel, or write an
unattributed audit record (only the first is safe). Found two more confirmed,
live instances beyond C1/C2, both production authorization gaps, not test
artifacts:

- **`AddGroupMemberProxy` → `AddUserToGroup`**: `if actorID != 0 {
  validateGroupJoinRoles(...) }` treats "no session" (a legitimate local-CLI
  exemption) and "a node credential" (the most widely distributed credential
  class in any deployment) as the same zero sentinel. A node credential can add
  a user to an admin-conferring group with the escalation-ceiling/SoD check
  never evaluated — confirmed reachable end-to-end.
  `TestRemoteStorageGroup_Membership_RealServer` is green for the wrong reason:
  it exercises a group with zero role grants, so the skipped check has nothing
  to check either way.
- **`ApproveRiskException`'s dual-control bypass**: the self-approval guard
  (`actorID == e.CreatedBy`) only catches a node-created-and-node-approved
  exception (both sides zero). A human-created exception approved by a node
  credential does not collide — dual control's entire point (a creator can't
  unilaterally suppress their own violation) is bypassable in exactly the case
  that matters.

Filed on #1524 (10 confirmed routes total now), plus two related-but-distinct
follow-ups: #1529 (several sites have NO actor-authority check at all —
`DeleteSoDPolicy` most concerning — a different question from the sentinel
collision) and #1530 (even a legitimate relay call persists
`CreatedBy=0`/`RevokedBy=0` on governance records — an audit-integrity defect).
**ADR-085** answers the design question underneath all of the above (should
node credentials carry their own narrow permission set instead of an
OR-bypass of the whole permission system — recommends yes, reusing ADR-030's
existing `machine_identity_roles`/`AuthorizePrincipal` mechanism) — accepted
and merged by Andrei directly (not part of this campaign's own authority).
None of #1524/#1529/#1530 is fixed in this campaign — every one needs a
production code change and a product decision.

**Practical implication**: any future test in this package using `createNodeToken`
against a route this campaign hasn't already audited should not be assumed to work
just because the pattern is dominant — check whether the specific handler validates
`actorID(r)`-gated authority (search the handler for `actorID(r)` directly) before
assuming a node credential is sufficient, and don't assume a failure matches a
known pattern without running it.

### Standing practice: adversarially verify a guard, not just that it exists

Added after the overnight run: writing a guard (a completeness test, a route
coverage check, a freshness assertion) and confirming it passes is not the same
as confirming it protects anything. Before reporting any of this campaign's three
CI-level guards (G80's reflection completeness test, #1511's AST route-coverage
guard, C5's exclusion-freshness/leg-completeness checks) as done, each was
adversarially tested: make the exact change the guard exists to catch, confirm it
goes red with a usable error message, revert, confirm green again. All three
guards fired correctly on every mutation tried (9 mutations total across the
three guards — see the PR that lands this writeup for the full table), including
reproducing the ORIGINAL historical defect this campaign started from (G80's
`ID` field was once not compared in `diffSecretUpdate` at all; removing it again
and re-running the test now fails the `ID` subtest specifically, by name). One
near-miss during testing is worth recording: the first route picked to test the
AST guard's route-deletion detection was already in `knownUnresolvedWireCalls`
(a path built via string concatenation with a non-constant), so deleting its
router registration didn't fire — correct behavior for an already-known blind
spot, not a guard failure, but a reminder to check which detection path a test
target actually exercises before trusting a single negative result.

### C1 — PR #1525, merged 2026-08-22

See above.

### C2 / C3 — PR #1528, merged

Six fixture repairs (bcrypt length, CSV headers, secret-dependency IDs,
setup-token `SubjectUserID`, the `CreateUserWithRoleGrantsProxy` actorID(r)
fix) and four risk-exception quarantines (2 correctly attributed to #G79's
removed route from the start, 2 corrected mid-campaign per #1531 above). Every
fixture repair verified red-then-green by breaking its subject first.

**Quarantine list, verified against the actual `t.Skip` calls in
`server/http/remote_storage_risk_exceptions_test.go`** (grepped directly, not
copied from an earlier draft of this document — 2026-08-23):

| Test | Reason | Issue |
|---|---|---|
| `TestRemoteStorageRiskExceptions_CreateGetListUpdate_RealServer` | `UpdateRiskExceptionProxy` deliberately unregistered (#G79) | #1511 |
| `TestRemoteStorageRiskExceptions_ActiveOnlyExcludesRevoked_RealServer` | same — also calls the unregistered route | #1511 |
| `TestRemoteStorageRiskExceptions_RevokeIfNotRevoked_ConditionalRace_RealServer` | wire-contract mismatch, not actorID(r) — see #1531 | #1531 |
| `TestRemoteStorageRiskExceptions_ApproveIfPending_ConditionalRace_RealServer` | same wire-contract mismatch | #1531 |

No other `t.Skip` in `server/http` or `server/http/handlers` belongs to this
campaign (3 unrelated pre-existing skips found in `server/http/handlers` —
a SQLite ILIKE limitation, an SSOLoginState seeding limitation, and one
`t.Skip("CreateSecret failed:", err)` in `handlers_s10_test.go:106` that uses
`t.Skip` where `t.Fatal` looks more appropriate — noticed, not chased, not
part of this campaign).

### C4 — PR #1537, merged 2026-08-23

Re-enabled `server/http`, excluded since 2026-04-27 with no leg even if
un-excluded. Investigated whether the package was genuinely healthy before
sharding: ran the full unsharded package locally with `-race -timeout 3600s`
— 1904.015s, zero failures beyond the 2 already-fixed-on-main C1-scope
fixtures (the branch it ran on predated #1525's merge). Confirmed healthy and
slow, not deadlocked — the earlier 20-minute goroutine-dump "failure" that
started this investigation was the default `go test` timeout cutting off a
still-running suite, not a hang.

Sharded 6 ways (`http-1..6`) by test name, generalizing handlers-1..4's
existing mod-N mechanism (`run_filter_for_shard`, added in C5) rather than
reimplementing it: 1904.015s × ~1.7 (local→runner factor, same one
established for `internal/core`) ≈ 3237s runner-equivalent; 6 shards puts each
at ~540s predicted, ~30% of the 1800s timeout. Measured on the real runner
(job wall-clock, includes checkout/setup overhead): 662s–724s per leg — see
the refreshed headroom table in "Task 3" above.

Also swept in `internal/cli$` and `internal/storage/remote` (both measured
clean: 0.558s and 31.201s locally, zero failures) into `root-4`'s catch-all —
too small to need a dedicated leg. Closed #1533/#1534/#1535.

### C5 — PR #1536, merged 2026-08-23

Replaced the bare `grep -v` exclusion patterns with a single source of truth
(`scripts/ci-test-legs.sh`) shared between the test-suite matrix step and two
new independent jobs: `exclusion-freshness` (fails, not warns, when a
`TEMPORARY` exclusion is older than 30 days) and `assert-leg-completeness`
(fails when any package is covered by neither a leg nor the exclusion table —
the direct guard against the failure mode that let `server/http` sit dark for
~4 months). Both guards verified to actually fire (see the standing-practice
note above and this PR's own description for the exact mutations used).

## Stopping rule: classify reach, fix human-reachable, file machine-only, stop

Adopted after #1542's fix (routing 4 raw-storage-bypass RBAC proxy routes through
`internal/core`) organically grew into fixing a 5th (`RemoveMachineRoleProxy`) and
building a whole new completeness guard, whose OWN findings (#1545, #1546) then needed
their own reach classification before any further work was justified. Without an
explicit boundary, "I found a related gap while fixing this one" has no natural stopping
point — every fix's blast radius touches a shared checkpoint (a ceiling function, a
storage primitive) with its own set of callers, and each of those callers can look like
"just one more thing to check while I'm here."

**The rule:**

1. **Classify reach before deciding whether to fix.** For any candidate (a ceiling
   exemption, a raw-storage bypass, an authority check that might be skippable) the
   first and only question that decides urgency is: can a real, network-authenticated
   HUMAN session trigger this, or is it structurally limited to a machine credential (or
   a genuinely-trusted local/embedded call path)? Answer it with file:line evidence —
   trace the actual call chain and the actual authentication layer (does `UserID`/
   `actorID` ever come from a real human session with the vulnerable value, or only from
   a machine token by construction) — never by assumption. This is the same question
   that made #1542 top priority over #1524's other findings, and the same rigor #1545's
   classification used (`server/middleware/auth.go`'s "UserID is 0 for ANY machine
   token" doc comment, traced against every real call site of the two functions in
   question) to conclude machine-only, not human-reachable.
2. **Human-reachable: fix it now, it outranks other open work.** Matches #1542's own
   framing ("outranks everything else open").
3. **Machine-only: file it, with the reach classification and evidence in the issue
   body, and stop.** Do not fix it in the same sitting just because the shared checkpoint
   is already open in an editor. Filing with real evidence (not a bare TODO) is what
   makes "later" credible — see #1545, #1546, #1547, none fixed on discovery, each with a
   full evidence trail so a future session doesn't have to re-derive reach from scratch.
4. **"Stop" means stop working THIS finding, not stop auditing.** This rule does not
   relax the standing exhaustive-coverage practice elsewhere in this campaign (guards and
   finders should keep being comprehensive) — it bounds what happens the MOMENT a finding
   is confirmed machine-only: classify, file, move on. It exists specifically to stop a
   single fix from cascading into fixing every sibling discovered along the way without a
   fresh, explicit decision to expand scope.

**Applied so far:**

- **#1545** (`AssignPermissionToRole` self-permission-bundling ceiling,
  `internal/core/rbac_management.go:90`; `BulkDeleteSecrets` per-secret ACL/ownership
  check, `internal/core/bulk_delete.go:100,116`) — classified machine-only, confirmed by
  exhaustive call-site tracing (every real HTTP/gRPC caller with a `UserID`-carrying
  session self-blocks at its own upstream `Authorize()` pre-check before ever reaching
  the exemption; the only zero-actor callers are a machine credential — `UserID` is 0 for
  ANY machine token type, `server/middleware/auth.go:66-68` — or an already-established
  trusted local pseudo-actor, boot-time reconcile for the first and embedded CLI for the
  second). No human account can ever present `UserID==0` (verified against
  session/PAT/bootstrap/impersonation/OIDC-federation code paths, `server/middleware/auth.go`
  and `server/grpc/interceptors/auth.go`). Filed, not fixed; full evidence trail on the
  issue.
- **#1546** (`TransitionMembershipProxy` bypassing `core.TransitionMembership`'s
  activation ceiling + role-grant/revoke side effects) — reach genuinely unresolved (may
  be a real gap, or may be safe-by-design if the side effect already lands via a separate
  relayed call from the downstream's own `core.TransitionMembership`) — filed with both
  hypotheses stated, not guess-fixed.
- **#1547** (the raw-storage-bypass guard's 18-route scope losing coverage, demonstrated
  by #1545/#1546 both being found outside it) — classification of the guard's own
  false-positive pattern filed as its own follow-up, not implemented mid-session.
  Re-measuring the guard's real detection logic (not a cruder estimate) against every
  handler in `server/http/handlers`, not just the 18 already-classified routes, found
  **149 flagged call sites**: 90 (60%) mechanically excludable as read-shaped storage
  methods (`Get*`/`List*`/`Count*`/`Export*` — a read confers no new access, so there's
  no ceiling to bypass), leaving **59 write-shaped candidates**. Of those 59, individual
  investigation (not the keyword-match heuristic alone, which proved unreliable in both
  directions — see #1547) confirmed 7 as safe: 3 with no independent ceiling to bypass
  (`ClearProjectSecretOwnershipProxy`, `DeleteSecretACLsByUserAndProjectProxy`,
  `DeleteExpiredRoleGrantsProxy` — each core "wrapper" is audit-only bookkeeping, not a
  gated primitive) and 4 deliberate, already-documented exceptions
  (`CreateUserWithRoleGrantsProxy` — C2, one-atomic-transaction requirement, ADR-028;
  `RemoveGlobalAdminRoleGuardedProxy` — no real transaction spans the HTTP hop, guard
  must live at the row-owning server; `DeleteProjectProxy`/`DeleteProjectIfEmptyProxy` —
  same reasoning as `RemoveGlobalAdminRoleGuardedProxy`, `DeleteProjectIfEmpty` is a
  purpose-built atomic storage-layer primitive enforcing `DeleteProject(force=false)`'s
  guard across the hop, #528). **That leaves 52 genuinely unresolved** — the measured
  remaining backlog for this bug class — of which 1 (`TransitionMembershipProxy`)
  already has its own filed issue (#1546) and 51 have not been individually investigated
  at all. This is the number a future session should treat as the actual size of the
  #1542-shaped backlog, not the 18-route scope's apparent completeness.

A future session picking up #1545/#1546/#1547 (or whatever the guards in this campaign
surface next) should apply the same rule: classify reach first, fix only what's
human-reachable, file the rest with evidence, and treat "filed" as a legitimate stopping
point, not an unfinished task to feel behind on.

## Overnight triage of the 52 unresolved candidates (2026-08-23 → 2026-08-24)

Full results: `docs/g80-raw-storage-bypass-enumeration.md` (the reproducible 58-candidate
baseline, and why it supersedes the 59 above — see below), `docs/g80-raw-storage-bypass-blind-spots.md`
(five categories this guard cannot see, named not chased), `docs/g80-raw-storage-bypass-triage.md`
(per-candidate table with file:line evidence), and `docs/g80-overnight-handoff-2.md`
(executive summary — **read this first**, it flags several human-reachable, unfixed
findings prominently).

**The "149 flagged / 90 read / 59 write-shaped" figures immediately above (from the
original #1547 entry) could not be reproduced and should be treated as incorrect.** Two
independent implementations of that entry's own stated methodology — a regex/line-scan
version and an AST-based version (`scripts/analysis/raw_storage_bypass_enumerate.go`,
committed, immune to line-wrapping by construction) — both produce **145 flagged / 87
read-shaped / 58 write-shaped**. Multi-line method chains and variable/interface dispatch
were checked directly as candidate explanations for the gap and ruled out (zero instances
of either in the current codebase). 58, not 59, is now the reproducible baseline; run
`go run scripts/analysis/raw_storage_bypass_enumerate.go` to regenerate it.

Of those 58 candidates, 50 were investigated tonight (the 7 already resolved above, plus
`TransitionMembershipProxy`/#1546, were left as-is).

**Result: 35 of the 50 are `real` (a genuine ceiling bypass), and all 35 are
`human-reachable`** — not machine-only. The stopping rule's informal extrapolation from
the 7-item sample (implying most of the remainder would be safe, ~11-12%) was wrong in
the dangerous direction: the actual true-positive rate among the unresolved remainder was
70%. **None of the 35 have been fixed** — this was classification only, per explicit
instruction for the overnight session; unsupervised edits to authorization code were
out of scope regardless of how many findings turned out human-reachable. GitHub issue
filing and the #1547 Slack post are both blocked on `gh auth` being broken (invalid
keyring token) — see the handoff doc for ready-to-file issue content.

**State the number as: 35 of 58 real and human-reachable, within the guard's stated
reach (server/http/handlers only) — with five further categories (multi-line chains,
now fixed; variable/interface dispatch; wrapper-mediated calls; the read-shaped naming
heuristic; non-handler layers — gRPC/CLI/background jobs) named as unexamined in
`docs/g80-raw-storage-bypass-blind-spots.md`, not folded into this count.** 20 files
outside `server/http/handlers` (7 gRPC service files, 13 CLI command files) make raw
storage calls this guard never looks at.

**This is now the top-priority open item in the G80/#1542 lineage** — worse in aggregate
than the original G80 bug and on par with or worse than #1542's own motivating finding.
Do not treat "filed, not fixed" as equivalent to low-urgency here; the stopping rule's
own clause 2 ("human-reachable: fix it now, it outranks other open work") applies to all
35 — it was deliberately not invoked tonight only because this was an unsupervised
overnight session and authz-code changes need a human in the loop, not because the
findings don't qualify.

## Stale-test disposition: premise-impossible vs. premise-true-but-unverified (2026-08-24)

Merging #1550 (the 23-handler deletion) into main broke 3 `internal/core` tests
(`login_lockout_remote_test.go`'s `TestLockout_RemoteStorageGenuinelyPersistsAndLocks`,
`TestLockout_RemoteStorageGenuinelyClears`, `TestUnlockUser_RemoteStorageGenuinelyPersistsAndAudits`)
plus ~50 `internal/storage/store` tests exercising the same 22-23 now-stubbed
`RemoteStorage` methods. Every prior "stale test" disposition in this campaign has been
a **coverage gap**: the test was fine, the code under it changed, update the fixture.
This is the first one that isn't — worth naming the distinction explicitly so it doesn't
get collapsed into the same bucket next time:

- **Premise-true-but-unverified**: the test exercises a real, reachable code path, but
  its expectations (a fixture, a mock response, a hardcoded count) drifted from current
  behavior. Fix the fixture, don't delete the test — the reachability claim still holds,
  only the assertion is wrong. This is every prior stale-test fix in C0–C5 above (fixture
  gaps, RealServer quarantines, coverage assertions).
- **Premise-impossible**: the test's OWN SETUP constructs a topology that cannot occur in
  any real deployment, independent of what it asserts. No fixture fix rescues this — the
  scenario itself is fiction. Delete the test (and any helper that exists solely to serve
  it), don't quarantine or paper over it.

The 3 `internal/core` tests are premise-impossible: `newRemoteLockoutCoreAgainst` builds
`&KeyorixCore{storage: rs}` as a raw struct literal, never touching
`internal/config.Config` or `Config.Validate()`. That topology — a server process backed
by `RemoteStorage` — is rejected UNCONDITIONALLY by `validateRemoteStorageNotServer`
(`internal/config/config.go:2057`), verified by checking both guard call sites
(`server/main.go:75` in `main()`, `server/main.go:302` in `initializeCoreService()`, the
ONE function among 27 `core.NewKeyorixCore` call sites repo-wide that ever feeds
`server/http/handlers`) and confirming neither has a bypass. No amount of fixing the
fake-upstream HTTP mock's response shape would make the scenario real; the only correct
fix is deleting the test.

**The check that catches this, sharpened from the stopping rule above: a Go call graph
proves a function CAN be called, not that the call CAN be constructed in a real process.**
Tracing `server/http/handlers/catalog.go → core.UpdateProject → storage.UpdateProject`
finds a real call chain — but whether that chain ever executes with a `RemoteStorage`
receiver depends on whether anything can actually construct that pairing at runtime, which
is a separate question a call graph alone cannot answer. Verify the WIRING (what
constructs the receiver, and does anything gate that construction), not just the CALL.
See CLAUDE.md's "Engineering practices" for the general form of this rule and four
concrete instances from this campaign that cut in both directions.

The anti-silent-no-op guarantee these 3 tests protected (backlog #529: prove
`RemoteStorage` write methods fail LOUDLY, not silently, when unsupported) is preserved by
different, still-live machinery: `RemoteStorage.UpdateLoginLockoutState` (and the other 22
now-stubbed methods) return `errUnsupportedRemote` unconditionally — a loud, immediate
error, not a silent no-op — and `TestRemoteStorageWireCalls_HaveMatchingRoute`
(`internal/storage/store`) independently catches any wire call left with no matching
route. Nothing about #529's original finding is unprotected; the protection just moved.
