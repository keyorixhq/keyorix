# Cross-layer authz differential harness: report

Branch `test/authz-differential-harness`, based on origin/main `bd16d6921`.
Layers: core called directly, REST (`server/http`), gRPC (`server/grpc`).
The CLI layer was replaced by gRPC (Phase 0 decision: since ADR-108 the CLI is
a REST-only client with no authorization decisions of its own).

## Phase 0 (summary)

Existing cross-layer mechanisms and what they leave uncovered: see the Phase 0
report in the session. The one behavioural cross-layer harness is
`server/http/grpc_rest_authz_parity_fuzz_test.go`. It covers REST vs gRPC
only, for secret read/create/update/delete and role assign, has no reference
model, and has no core-direct leg.

## Phase 1: operation matrix

### How it was derived

`go run ./devtools/authzmatrix -md server/authzdiff/MATRIX.md -json server/authzdiff/matrix.json`
(loads the full program, ~1-2 min). Method and blind spots are in the header
comment of `devtools/authzmatrix/main.go`. In short:

- **Population**: REST from `scripts/e2e/routes.json` (384 routes,
  AST-derived and freshness-checked by `TestRouteInventoryIsCurrent`). gRPC
  from every `pb.Register<X>Server(s, impl)` call (87 methods, named by the
  generated `_FullMethodName` consts).
- **Handler resolution**: the last argument of the chi registration call on
  each route's `router.go` line, resolved through `go/types`. 384/384
  resolved after two fixes (routes.json records the statement's start line,
  not the verb's; and `factory().ServeHTTP` interface method values).
- **Reach**: SSA walk following static calls, function-valued operands
  (closures, method values, callbacks) and interface invokes on interfaces
  `*KeyorixCore` implements. It stops at the first exported `*KeyorixCore`
  method. Handler-side calls on `core/storage.Storage` are recorded as
  raw-storage. There are 12 such REST and 20 such gRPC operations; all are
  `Get*`/`List*`/`HealthCheck` reads, and there are no direct writes.
- **Mutating**: REST = mutating verb, or key in faultops `knownOperations`.
  gRPC = key in `knownOperations` (faultops' read-prefix classifier). After
  normalizing chi.Walk's trailing slash, every REST mutating-verb route is in
  `knownOperations`, so there are no seed gaps.
- **Secret-value read**: reaches `decryptVersionValue` or a connector
  `GetSecret` inside core. Other decrypts (MFA secrets, notification URLs,
  dynamic-secret admin credentials, all through the same `ports` encryptor)
  are reported as `decrypts_internally` and are not in scope by themselves.
- **Core refusal** (per core entry, derived from the refusal mechanism, not
  from guard names): `typed` / `untyped` / `none`. See `OUTCOMES.md`.

### Calibration

- **Green**: all 11 rows pass. The 9 live FIX-1 entry points
  (`AssignRoleToGroup`, `AssignGroupRoleWithExpiry`, `AssignMachineRole`,
  `AddUserToGroup`, `CreateUserWithAssignments`, `InviteToProjectWithLink`,
  `InviteGlobalWithLink`, `ApproveAccessRequestWithExpiry`,
  `TransitionMembership`) each reach `requireGranterHoldsRolePermissions`.
  The handlers the SSA walk finds match an independent text-grep oracle (call
  sites plus enclosing func, derived by hand).
- **Extra paths the grep missed**: the walk also found
  `POST /access-requests/bulk-approve` reaching
  `ApproveAccessRequestWithExpiry` through `BulkApproveAccessRequests`, a
  transitive path inside core that the call-site grep cannot see.
- **Red**: `calibrateSelfTest` plants three mismatches (a nonexistent gRPC
  twin, a live entry marked dead, a guard deleted from every op's reach).
  Calibration goes red on each. The tool refuses to write output if any
  stays green.

### Results (each is a matrix result, not a fix)

1. **FIX-1's entry list names two dead methods.** `InviteToProject` and
   `InviteGlobal` (`internal/core/invitations.go:305/369`) have no
   production caller. The live paths are `InviteToProjectWithLink` and
   `InviteGlobalWithLink`. Both are guarded, so this is not a bypass. But
   the FIX-1 note and any test aimed at the old names cover dead code.
   Calibration keeps both as "expected dead" rows that go red if a caller
   appears.
2. **Scope**: 211 REST and 46 gRPC operations are in scope (mutating or
   secret-value read), across 278 non-infra core entry rows. There are 59
   rows with both REST and gRPC, 213 REST only (ADR-105: gRPC is partial by
   decision), and 6 gRPC only.
3. **The 6 gRPC-only rows are authorization path differences, not missing
   REST routes.** gRPC calls core authz helpers that REST never calls,
   because REST gates in middleware instead:
   - `AuthorizeSecretPrincipalForSecretAction` (gRPC secret
     update/delete/ACL grant/revoke/auto-rotate/share)
   - `GetSecretForValueRead` (gRPC value read; REST uses
     `GetSecretValueResolved`/`GetPermittedSecretValue`)
   - `GetRoleWithPermissions` (gRPC UpdateRole)

   Same operation, different authorization code. These are the highest-value
   Oracle 1 targets outside the existing parity fuzzer's coverage.
4. **202 of 278 core entries do no authorization refusal of their own**
   (`core refusal = none`). The transport is the only gate. In the
   priority families this includes `CreateGroup`/`UpdateGroup`/`DeleteGroup`,
   `RemoveUserFromGroup`, `Create/Update/DeleteProject`,
   `CreateMachineIdentity`, `Classify*`, `RevokeMachineToken`,
   `TransitionMachineIdentity`, `RevokeInvitation`, `ResendInvitationLink`,
   `RejectAccessRequest`, `WithdrawAccessRequest`, `RemoveProjectMember`,
   `RemoveMachineRole` and `RemoveRoleFromGroup`. For these the core-direct
   leg is excluded from Oracle 1 (intended difference ID-2) and REST vs gRPC
   carries the comparison.
5. **Asymmetries inside the guarded families**:
   - `AssignMachineRole` is typed, but its inverse `RemoveMachineRole` is
     `none`.
   - `AssignRoleToGroup` is typed, but `RemoveRoleFromGroup` is `none`.
   - `ApproveAccessRequestWithExpiry` is typed, but `RejectAccessRequest` is
     `none`.

   Revocation being transport-gated only is plausibly intended (removing
   access cannot escalate). Flagged for the Phase 3 classification, not
   asserted as a bug.
6. **Untyped refusals on live priority paths**: `ApproveSecretAccessRequest`
   and `RejectSecretAccessRequest` (`errAdminAuthorityRequired`), and the
   SCIM group provisioning paths (`ErrorNotAuthorized`). These are expected
   to produce mapping-gap pairs in Phase 2.
7. **Faultops' gRPC mutating classifier disagrees with REST on one
   operation**: federated read is `POST /connect/{name}/secret:read`
   (mutating by verb) on REST and `ConnectService.ReadSecret` (read-shaped)
   on gRPC. It is in scope either way because it is a secret-value read.

### Phase 2 plan: priority operations and layer coverage

| Family | All three layers | Core + REST only |
|---|---|---|
| groups | Create/Update/Delete/Restore group, add/remove member | assign/remove group role |
| projects | Create/Update/Delete project | restore project, add/remove/set project member |
| machine identities | create, classify, issue/revoke token, transition | assign/remove machine role, migrate-from-user |
| invitations | — | create (project/global), resend, revoke |
| access requests | — | request, approve, reject, withdraw, bulk approve/reject |
| memberships | — | invite member, transition membership |

### Decision recorded for Phase 2

`errAdminAuthorityRequired` stays `other` (option (b), decided 2026-11-04).
Production code is not touched. Its pairs land in the mapping-gap bucket.

## Defect follow-up: untyped core refusals (not fixed here)

Two live refusal paths return an error that does not match
`core.ErrPermissionDenied`. A caller can only recognize them by message text,
and that text is translated. Each needs its own fix and closure row (red/green
proof) in a separate PR:

1. **Secret-access-request approve/reject**
   - Core: `ApproveSecretAccessRequest` and `RejectSecretAccessRequest`, which
     refuse through `requireAdminAuthorityAt` / `requireAccessRequestAuthorityAt`.
   - Error: `errAdminAuthorityRequired`, a plain `errors.New` in
     `internal/core/invitations.go`.
   - REST: `PUT /api/v1/secret-access-requests/{requestId}`.
   - Likely fix shape: build it with `newPermissionSentinel`, or wrap it with
     `markPermissionDenied`.
2. **SCIM group provisioning**
   - Core: `ProvisionSCIMGroup`, `PatchSCIMGroup` and `ReplaceSCIMGroup`
     (`scim_groups.go`), which refuse with i18n `ErrorNotAuthorized`.
   - REST: `POST/PATCH/PUT /scim/v2/Groups...`.
   - `errors_permission.go` lists this as a known non-matching refusal.
     Whether SCIM should map to the house 403 convention is open: ADR-096
     excludes SCIM from the anti-enumeration migration.

## Do keyorix-mcp and keyorix-k8s-sync reach core directly?

**No. Both are REST-only clients.**

Evidence: `go list -deps ./cmd/keyorix-mcp ./cmd/keyorix-k8s-sync`, filtered
to this module, lists only `internal/netutil`, `internal/mcp`,
`internal/secretenv`, `internal/k8ssync` and the two `cmd` packages. No
`internal/core`, `internal/storage` or `server/*` package appears anywhere in
either binary's dependency graph (indirect imports included).

Transport:

| Binary | Keyorix REST calls |
|---|---|
| `internal/mcp` | `GET /api/v1/secrets/value?ref=...` and `GET /api/v1/secrets` |
| `internal/k8ssync` | `GET /api/v1/secrets?...`, `GET /api/v1/secrets/{id}?include_value=true` and `GET /api/v1/projects/{id}/environments` |

Its `/api/v1/namespaces/...` calls are the Kubernetes API, not Keyorix. So
both inherit REST's authorization exactly. Neither needs a layer in this
harness: `secret.value.byref` and `secret.value.byid` cover their two
secret-value paths.

## Design observation (possible ADR): core methods that do not authorize

This is Phase 1 result 4 above (finding 3 in the Phase 1 session summary).
Recorded as an observation, not a defect.

202 of 278 in-scope core entry points perform no authorization refusal of
their own. The transport (router middleware or gRPC service code) is the only
gate, and the actor id is often used only for audit. The pattern is
consistent with ADR-108: core is reached only through REST, gRPC and the
offline `admin` subcommands. The CLI and the two satellite binaries never
link core.

It still leaves a standing risk. Any new in-process caller of core inherits
zero authorization for those methods, and nothing machine-checks that every
caller sits behind a gate:

- a third transport;
- a scheduler or job that acts "as" a user;
- a future SDK-in-process mode.

The harness makes the split visible (`core refusal = none`, intended
difference ID-2) but does not enforce it.

Questions an ADR would settle:

1. **Is "core trusts its caller" the intended contract?** If so, state it,
   name the sanctioned callers, and add a guard that fails when a new package
   imports `internal/core` and calls a `none`-class method. The
   import-allowlist pattern from `TestNoNewRemoteStorageImportersOutsideAllowlist`
   would fit.
2. **Or should actor-taking methods authorize in core**, with transports
   as defence in depth? This is a large change; `matrix.json` is the
   worklist.
3. **Grant-guarded, revoke-transport-only asymmetry** (Phase 1 finding 5):
   intended or not? Revocation cannot escalate, but it can lock someone out.
4. **D4: what does secret ownership grant?** (Recorded as a design question
   in Phase 4.)
   - Core's `EnforceSecretActionPermission` (`permissions.go:112`) says write
     is granted to "owner, an allowlisted share, an ACL or a role".
   - Both transports gate the route on project RBAC (`secrets.write` /
     `secrets.delete`) before core runs. So an owner without that permission
     can never update or delete their own secret, and core's owner branch is
     unreachable for exactly the users it seems written for.
   - Options:
     - (a) Ownership grants nothing on its own. Remove the owner branch from
       core, or keep it only as an additional narrowing.
     - (b) Ownership is a grant. Then the transports must let an owner through
       their route gate (e.g. a secret-scoped gate that consults ownership the
       way `RequireScopedSecretPermission` already consults shares and ACLs).
     - (c) Ownership is meaningful only together with RBAC. Document that, and
       guard it with a test that an owner without the RBAC permission is
       refused on every transport. This is today's behaviour, unguarded.
   - The harness pins today's behaviour as bucket D4. Whichever option is
     chosen, the D4 rule changes, and STRICT then catches any drift.
5. **D5: core does not check account state.** A suspended principal is
   refused by both transports (its credential is rejected), but core methods
   called directly do not consult account state. Same contract question as
   1: if core trusts its caller, account state is a transport duty and should
   be stated as such.

## Phase 2: harness

### What was built (`server/authzdiff`, test-only package)

| File | Role |
|---|---|
| `world_test.go` | Seeds a SQLite template once: production migration via `fuzzworld.Bootstrap`, then principals and fixtures through core/storage. Every leg of every case gets its own byte copy of it, with a fresh core plus router or gRPC server. Synthetic data only. |
| `model_test.go` | The reference model (~60 lines of logic). Reads the grant tables directly and answers Authorize over each role's actual permissions, plus the FIX-1 ceiling and the documented share owner rules. |
| `outcome_test.go` | One mapping function per layer, implementing `OUTCOMES.md` exactly. Core errors are matched by identity only. |
| `ops_test.go` | 28 operations, each with a model requirement and one function per layer. `coreEnforced` is derived from `matrix.json` at runtime, never hand-set. |
| `harness_test.go` | Runner, admin positive control, Oracle 1/Oracle 2 classifier, JSONL sink. The sink writes no values, bodies or requests. |
| `sweep_test.go` | `TestAuthzDiffSmoke` (default `go test`, ~4s), `TestAuthzDiffSweep` (`AUTHZDIFF_SWEEP=1`, exhaustive) and `FuzzAuthzDiff` (registered in `scripts/fuzzing/targets.d`). |

**Principals** (fixed set):

- no role: `CreateUser`'s `system_viewer` baseline is removed;
- `project_viewer`@A;
- `project_admin`@A;
- bootstrap global admin;
- `release-manager`, a custom role with a fuzzed permission subset, held at A
  or global (FIX-1 shape);
- a machine token holding the custom role @A;
- actor id 0 (core only);
- `project_admin`@A with an expired grant.

**Fuzzed or swept dimensions**: operation × principal × target (A, B,
global) × granted role (`project_viewer`, `release-manager`, `project_admin`,
`editor`) × the custom role's permission subset (all, none, each single one
of 8) × the custom grant's scope.

**Operations covered:**
- divergent secret ops: update, delete, ACL grant/revoke, auto-rotate, share,
  value read by ref, value read by id;
- groups: create/update/delete, member add/remove, role assign/remove;
- projects: create/update/delete;
- machine identities: create, token issue/revoke, transition, role assign;
- invitations: create/revoke;
- access requests: approve/reject;
- memberships: transition.

### Run evidence (at this branch, SQLite)

| Run | Result |
|---|---|
| `go test ./server/authzdiff/` | PASS (4.1s). The smoke test asserts every op's admin positive control is `allowed` on every layer that has the op. |
| Exhaustive sweep | 2,844 cases × 3 layers in 45s, of which 82 cases have an O1/O2 class. 105 legs per layer are uncalibrated by design (see `OUTCOMES.md`). 79 cases are actor 0 (ID-1). |
| `FuzzAuthzDiff` | 60s at ~100 execs/s: no crash or failure. Disagreements are logged, not fatal, unless `AUTHZDIFF_STRICT=1`. |
| `go vet` and `gofmt` | Clean. `golangci-lint` was not run: the local binary is v1 and the repo config is v2. |

**These results are preliminary until Phase 3.** A clean area (e.g.
REST vs gRPC on secrets) means either a clean surface or a weak harness. The
planted defects in Phase 3 are what tell the two apart.

### Disagreements: preliminary classification (not fixed)

Classes: **real bypass**, **intended difference**, **mapping bug**. The last
covers both the harness and product error mapping.

**D1. REST vs gRPC: gRPC group mutations skip `users.read`.**
- **Shape**: real divergence, low severity. Classed "real bypass (low)",
  pending owner decision.
- **Ops**: `group.create`, `group.update`, `group.delete`,
  `group.member.remove`.
- **Principal**: custom role holding only `users.write` (or only
  `roles.assign`), globally.
- **Outcomes**: REST denied (403), gRPC allowed, model denied.
- **Cause**: the REST route group adds `RequirePermission(users.read)` on top
  of the write gate (`router.go:1019`). gRPC `GroupService` checks only
  `users.write` / `roles.assign` (`group_service.go:67/84/101/185`).
- **Impact**: the permission that authorizes the write is held either way,
  so this is a bypass of the `users.read` precondition, not an escalation.
  Whether `users.read` is meant to gate group writes is the owner's call. If
  yes, gRPC is missing it; if not, REST is over-strict.

**D2. Core-direct looser than every transport; no transport exposes it.**
- **Shape**: intended difference (layering). This is the "Design
  observation (possible ADR)" section above.
- **`secret.autorotate`** (60 cases): `SetSecretAutoRotate` with a plain
  `{enabled:true}` performs no authorization in core. Its only refusal (the
  untyped one the matrix saw) is on the backend-binding path. REST and gRPC
  deny, matching the model.
- **`group.member.add` and `group.role.assign`** (17 cases): core enforces
  the FIX-1 ceiling, but not the base `roles.assign` permission at the
  route's (global) scope. A `project_admin`@A, or a custom/machine principal
  holding `roles.assign` only @A, is allowed by core and denied by REST and
  gRPC (global gate).
  - This also shows the product question in the ADR section: groups are
    global objects, so a project admin cannot manage group roles even within
    their own project.
- **Refinement for the matrix**: its row-level `core refusal` class is too
  coarse here. `SetSecretAutoRotate` is `untyped` and `AddUserToGroup` /
  `AssignRoleToGroup` are `typed`, yet the base permission is transport-only
  on the paths exercised.

**D3. `IssueMachineToken` refuses every machine actor, despite its own
comment.**
- **Shape**: real defect, fails closed (over-denial), plus a mapping bug.
- **Op**: `machine.token.issue`.
- **Principal**: machine holding the custom role @A with `roles.assign`.
- **Outcomes**: core denied (`ErrPermissionDenied`), gRPC
  `PermissionDenied`, REST 500. The model allows.
- **Cause**:
  - `internal/core/machine_token.go:118-123` calls
    `requireMachinePrivilegeCeiling(ctx, ActorTypeUser, actorID, …)`. Its
    comment asserts "every caller … passes a real user's ID, never a machine
    principal's".
  - Both transports pass `actor.UserID` (0) for a machine actor, so the
    ceiling evaluates user 0 and refuses.
- **The comment's premise is false**: the route and RPC gates (`roles.assign`
  @project) admit machine actors.
- **No escalation**: it fails closed. But it is an assertion with no guard,
  exactly the "guard the condition, not the conclusion" case. Separately,
  REST maps the refusal to 500 (see M1).

**M1. REST returns 500 for typed permission refusals.**
- **Shape**: product error-mapping bug, not a bypass. All layers refuse.
- **Ops**:

  | Op | Cases |
  |---|---|
  | `machine.role.assign` | 16 |
  | `invitation.create` | 16 |
  | `accessrequest.approve` | 16 |
  | `machine.token.issue` | 2 |

- **What happens**: core returns `ErrPermissionDenied` (FIX-1 ceiling: "you
  do not hold permission X yourself", or `ErrMachinePrivilegeCeilingDenied`).
  The handlers (e.g. `changeMachineRole`, `machine_identities.go:606-625`)
  classify errors by message substring and fall through to 500.
- **Fix shape**: an `isPermissionRefusal(err) → 403` arm, as
  `secret_error_class.go` already has for secrets.

**M2. Machine actors on secret ACL grant and share get validation errors,
or 500.**
- **Shape**: over-denial with wrong status; no bypass.
- **What happens**: the transports pass `UserID=0` for a machine actor into
  `GrantSecretACL` and `ShareSecret`.
  - Core: "actor ID is required" / "sharedBy is required".
  - REST: 400 on ACL grant, 500 on share. gRPC: `InvalidArgument` on ACL
    grant, `Internal` on share.
- **Note**: share is owner-only, so a machine can never share, and a 500 is
  the wrong answer. ACL grant is gated on `secrets.manage`, which a machine
  can hold, and is then refused as malformed input.

**M3. Third untyped core refusal: `TransitionMembership`** (60 cases,
mapping gap).
- **What happens**: it refuses with a plain `errors.New`, "roles.assign is
  required at this membership's project to transition it".
- **Why REST is still right**: REST answers 403 because its gate refuses
  first.
- **Action**: added to the defect follow-up list (item 3) below.

**Mapping gaps that are correct as recorded:**
- `secret.share` core `other` (18): machine actors (`sharedBy=0`, see M2)
  and actor 0.
- **Harness mapping bug, fixed in Phase 2**: the core leg omitted
  `WithSelfMachineGranter` for machine actors. It produced 4 false
  `machine.role.assign` disagreements in the first sweep, which are gone in
  the second.

**REST vs gRPC on the divergent secret operations:**
- Across 584 secret-op cases, REST and gRPC agreed on every one: 79
  allow/allow, 485 deny/deny, 4 other/other (M2), 16 n/a (actor 0).
- The different authorization code paths found in Phase 1
  (`AuthorizeSecretPrincipalForSecretAction` vs REST middleware) produced no
  observable divergence for this principal and fixture set.
- **Coverage limit**: fixture secrets are admin-owned with no shares or
  ACLs for the probed principal. Share/ACL/owner-elevated paths are therefore
  only exercised from the admin side. Varying the owner is a follow-up.

### Defect follow-up list (updated)

Items 1–2 are in "Defect follow-up: untyped core refusals" above. Added in
Phase 2:

3. `TransitionMembership` untyped refusal (M3).
4. REST 500 for typed permission refusals in four handlers (M1).
5. `IssueMachineToken` ceiling evaluates machine actors as user 0, against
   its own comment (D3).
6. Machine actors on ACL grant/share: validation errors or 500 (M2).
7. gRPC group mutations do not require `users.read` (D1). Owner decision
   first.

## Before Phase 3: review follow-ups

### (1) Owner, share and ACL cases for the secret operations

**New fixtures.** Every secret op now runs against four secrets per project,
selected by the op arg:

| Secret | Owner | Share / ACL for the probed principals |
|---|---|---|
| s0 | admin | none (the Phase 2 baseline) |
| s1 | viewer principal | none. The viewer is a member of A, not of B. |
| s2 | admin | write share to the viewer, read share to the custom principal (A) |
| s3 | admin | ACL `secrets.write` for the viewer, `secrets.read` for the custom principal (A) |

- Shares and ACLs require the recipient to be a project member, and the
  probed principals are members of A only. So in project B, s2 and s3 are
  the "off" case.
- Every secret also carries the target user's ACL, which is what
  `acl.revoke` removes. ACLs are additive (`secret_acl.go`), so it does not
  change any probed principal's access.
- s1–s3 are **outside the reference model's domain**: Oracle 1 applies,
  Oracle 2 is recorded as `n/a`.
- **Positive control for s1**: the admin, or else the owner. An owner-only
  action refuses a non-owner admin.

**Result: REST and gRPC agree on every secret-op case.**

- 2,304 secret-op cases (8 ops × 4 secrets × 2 projects × all
  principals/variations).
- Every REST/gRPC pair is allow/allow, deny/deny or other/other. The 4
  other/other cases per secret in A are M2: a machine actor on share.
- Actor 0 is n/a on both transports.
- There are zero REST-vs-gRPC disagreements on any secret, owner, share or
  ACL fixture, in either project.

**Calibration:**
- The admin-or-owner control calibrates every s1 operation except
  `secret.share` (70 cases).
- Share is owner-only, and the owner (viewer) lacks `secrets.write` at the
  route gate. So no principal in the fixture set can share s1 on any layer.
  Those cases are uncalibrated by construction, not by a defect.

**New finding D4: ownership is a grant in core, but unreachable through any
transport.** This is a design observation, not a bypass.
- Core's `EnforceSecretActionPermission` (`permissions.go:112`) grants write
  to the "owner, an allowlisted share, an ACL or a role".
- Both transports gate the route on project RBAC (`secrets.write` /
  `secrets.delete`) before core runs.
- So the viewer, who owns s1 but holds only `project_viewer`, is allowed by
  core and denied by REST (403) and gRPC (`PermissionDenied`), for update and
  delete of s1 in A. That is 2 cases.
- The two transports agree. The open question is whether ownership is meant
  to grant anything at all; today it is dead code for owners without the RBAC
  permission. It belongs with the design observation above, as question 4.

### (2) Partition of the disagreements

`partition_test.go`'s `explain()` assigns each flagged case to a bucket by
an exact rule (op, principal kind, every layer's outcome), and
`AUTHZDIFF_STRICT=1` fails the sweep on any case it cannot explain. Known
findings are accepted. A new defect lands in `unexplained`; Phase 3 relies
on that.

**The 82 O1/O2 cases from Phase 2** (same case space, re-run):

| Bucket | Cases | Breakdown |
|---|---|---|
| D1 | 4 | gRPC group create/update/delete/member-remove without `users.read` |
| D2 | 76 | autorotate 59, group.role.assign 14, group.member.add 3 |
| D3 | 2 | |
| M1, M2, M3 | 0 | These are mapping-gap-only cases, not O1/O2; see the next table. D3 also shows the M1 symptom (REST 500) and is counted once, as D3. |
| unexplained | **0** | |
| **Total** | **82** | |

**Extended run with owner/share/ACL fixtures** (4,572 cases):

| Bucket | O1/O2 cases | Mapping-gap-only cases |
|---|---|---|
| D1 | 4 | |
| D2 | 252 | |
| D3 | 2 | |
| D4 | 2 | |
| M1 | | 48 |
| M2 | | 78 |
| M3 | | 59 |
| unexplained | **0** | **0** |
| **Total** | **260** | **185** |

D2 grew because autorotate now runs on four secrets, not one. It is the
same shape: core does not authorize a plain enable.

### (3) One root cause behind M1, M3 and both untyped refusals

**Root cause.** Core does have a typed refusal, `core.ErrPermissionDenied`,
but it is not the single, mandatory way to say "denied" on either side of
the boundary:

- **Core side.** Some refusals are built from plain text, so
  `errors.Is(err, ErrPermissionDenied)` is false:
  - `errAdminAuthorityRequired`, a plain `errors.New` (secret-access-request
    approve/reject);
  - `TransitionMembership`'s "roles.assign is required at this membership's
    project to transition it" (M3);
  - SCIM's i18n `ErrorNotAuthorized`.
- **Handler side.** Many handlers map core errors by **message substring**
  (e.g. `changeMachineRole`, `machine_identities.go:606-625`). They have no
  arm for a typed refusal, so a correctly typed refusal falls through to 500
  (M1, and D3's REST symptom).
  - The repo already knows the right shape: `secret_error_class.go`'s
    `isPermissionRefusal` does `errors.Is(err, core.ErrPermissionDenied)`.
    It is just only used by the secret routes.

**Proposed fix: one sentinel, enforced on both sides. Not implemented.**

1. **Core.** Every authorization refusal is built through the existing
   constructors in `errors_permission.go` (`newPermissionSentinel`,
   `permissionDeniedf`, `markPermissionDenied`), so it matches
   `core.ErrPermissionDenied`.
   - Concretely: `errAdminAuthorityRequired` becomes a
     `newPermissionSentinel`; `TransitionMembership`'s refusal uses
     `permissionDeniedf`; SCIM's `ErrorNotAuthorized` is wrapped with
     `markPermissionDenied`.
   - SCIM's response code can stay whatever ADR-096's SCIM exclusion decides;
     typing the error does not force a status.
2. **Transports.** One shared helper, e.g. `httpx.IsPermissionRefusal`
   (hoisted from `secret_error_class.go`), is called as the **first** arm of
   every handler error mapper, mapping to 403. The gRPC equivalent maps to
   `PermissionDenied`. Substring arms stay only for non-authz errors.
3. **Guards.** Each half of the contract gets a machine check:
   - Extend `TestEveryErrorPermissionDeniedRefusalIsTyped` from literal
     `i18n.T("ErrorPermissionDenied")` calls to every refusal the `refusal.go`
     derivation in `devtools/authzmatrix` classes as `untyped`. That class
     must become empty.
   - This harness: after the fix, M1/M3 cases stop being flagged at all
     (core and REST both say `denied`). Their `explain()` rules then match
     nothing, and `AUTHZDIFF_STRICT=1` catches any regression as
     `unexplained`.

Items 1–4 of the defect follow-up list close under this one change. Items
5–7 (D3's actor-type premise, M2's machine-actor handling, D1) are separate.

## Phase 3: prove it fires

### Method

1. Commit a clean baseline: a STRICT sweep of 4,572 cases with zero
   unexplained. Every known finding is partitioned by `explain()`.
2. Plant one defect in production code.
3. Re-run the full STRICT sweep. A planted defect matches no known finding's
   shape, so it must surface as `unexplained`, and only on the planted
   operation.
4. Diff every case's per-layer outcomes against the baseline.
5. Revert with `git checkout -- <file>` and confirm `git diff --stat` is
   empty.

### Results

| Plant | Production change (reverted) | Expected | Unexplained cases | Cases changed vs baseline | Named op |
|---|---|---|---|---|---|
| 1. Name-based role check on one entry point | `internal/core/machine_token.go` `AssignMachineRole`: `requireGranterHoldsRolePermissions` replaced by the pre-FIX-1 check (refuse only admin-tier role *names*, via `requireAdminAuthorityAt`) | Oracle 2 | 252: 185 O1/O2 and 67 mapping-gap | 254, all `machine.role.assign` | `machine.role.assign` ✔ |
| 2. One guard call removed from a handler | `server/grpc/services/machine_identity_service.go` `RevokeMachineToken`: `authorizeScoped(roles.assign)` removed | Oracle 1 | 59, all `O1(allow=grpc;deny=rest)` + `O2(grpc)` | 59, all `machine.token.revoke` | `machine.token.revoke` ✔ |
| 3. One router gate removed on a group op | `server/http/router.go`: `RequirePermission(users.write)` removed from `DELETE /groups/{id}` | Oracle 1 + Oracle 2 | 1: `O1(allow=rest;deny=grpc)` + `O2(rest)` | 1, `group.delete` | `group.delete` ✔ |

**Plant 1 detail.**
- **Oracle 2 caught the real end-to-end bypass**: 8 cases where core *and*
  REST allow and the model denies.
  - Every one is the exact FIX-1 shape: a custom role (or a machine token)
    holding only `roles.assign`@A grants `project_viewer` or `editor`, roles
    bundling permissions it does not hold.
  - The cases are the custom principal at A and at global scope, in both
    projects.
- **Oracle 1 also fired on 177 cases** (`allow=core;deny=rest`). With the
  ceiling gone, core alone admits principals that REST's `roles.assign` route
  gate still refuses. Expected: the ceiling was core's only check on this op.
- **67 mapping-gap cases**: `project_admin` grants (arg 2). They hit the
  plant's own `requireAdminAuthorityAt`, whose `errAdminAuthorityRequired` is
  untyped, which is defect follow-up item 1 seen from another angle.

**Plant 3 detail.**
- Only 1 case surfaced: custom role, global scope, permission subset =
  `users.read` only. The route group's outer `users.read` gate still filters
  every other principal. Only a principal holding `users.read` but not
  `users.write`, globally, can tell the inner gate's absence apart.
- **Detected, with the minimum possible margin.** Sensitivity here depends
  on the custom role's single-permission variations. It does not depend on
  the fixed principals, none of which holds `users.read` without
  `users.write` globally.

**Reverts and clean run.**
- After all three reverts: `git diff --stat` is empty.
- The final STRICT run passes: 4,572 cases, partition D1 4 / D2 252 / D3 2 /
  D4 2 / M1 48 / M2 78 / M3 59, unexplained 0.
- The per-case outcome diff against the pre-plant baseline is empty.
- Each plant changed outcomes on its own op only. The other ~4,300–4,500
  cases were identical across all five runs, so the harness is
  deterministic.

### What this does and does not show

- **It does show:** a removed guard is detected whether it sits in core
  (plant 1, Oracle 2), a gRPC service (plant 2, Oracle 1) or the REST router
  (plant 3, both), and the report names the planted operation.
- **It does not show** detection for defects a fixture cannot reach:
  - environment-scoped grants;
  - MFA-required projects;
  - PAT restrictions;
  - suspended accounts;
  - operations outside the 28 covered (see the matrix for the full in-scope
    list);
  - secret owner/share/ACL semantics under Oracle 2 (Oracle 1 only).

## Phase 4: generated principals and operations, new principals, permanent self-test

### (1) Generated principals

**What replaced the hand-picked set.** The hand-picked custom/machine
permission subsets are gone. Per (operation, target, arg), `genVariations`
derives the requirement set R: the gate permissions plus every permission of
every role the op grants, read from the database (`requirementPerms`). From R
it generates these permission sets:

- R itself;
- every leave-one-out R∖{p};
- R∖{p} plus each single distractor permission;
- U∖{p};
- each single permission;
- the empty set.

**How each set is held.** Each set is held three ways:
- directly, by the custom user;
- through a group (`g-custom`);
- by the machine principal.

Scopes are the op's project, the other project and global. Machines are
never global.

**Universe and named principals.**
- `TestRequirementsWithinUniverse` (default `go test`) fails if an op
  requires a permission the generator cannot express. It is how
  `audit.read` (bundled by `project_auditor`) was found missing from the
  universe and added.
- The named principals stay: no role, viewer@A, project-admin@A, global
  admin, actor 0, expired grant, plus the two added in (3). Each tests a
  mechanism a permission set cannot express.

**Plant 3 now fails on many cases.** The shape that exposes a missing
`users.write` gate on `group.delete` ("holds `users.read`, not `users.write`,
globally") is now generated 26 times. The count is the D1 population on
`group.delete`, which needs exactly that principal shape. In Phase 3 it was
generated once. The plant self-test below asserts at least 10.

### (2) Operations derived from matrix.json; coverage

- **Population and coverage are derived:**
  - the population is every in-scope REST op of the six families in
    `matrix.json`, classified by route path (`routeFamily`);
  - an op covers a route when the REST request it actually builds matches
    the route's template (`opRoute`).
- `COVERAGE.md` is generated, and `TestCoverageIsCurrent` fails when it is
  stale.
- `TestEveryOpBindsAMatrixRoute` fails if any op's request matches no matrix
  route (mis-built or out of scope).
- The sweep runs ops in family order.
- **What is still hand-written:** the per-op binding. That means which
  fixture fills which path parameter or body field, and the core and gRPC
  calls. The request bodies come from handler structs, not from a schema the
  harness could generate from. That limit is stated, not hidden.

20 operations were added in family order:

- **groups:** restore;
- **projects:** restore, environment create and restore;
- **machine identities:** classify, classify token, role remove, OIDC binding
  create and delete, migrate-from-user;
- **invitations:** global, resend;
- **access requests:** create, withdraw, bulk approve, bulk reject;
- **memberships:** invite member, add, set role and remove project member.

New fixtures support them: soft-deleted group, project and environments, a
target machine role, an OIDC binding, a migration user, fresh users, and a
requester principal. Seeded setup tokens are backdated so the 60s resend
throttle never trips the controls.

| family | in-scope routes | covered |
|---|---|---|
| groups | 8 | 8 |
| projects | 8 | 6 |
| machine identities | 11 | 11 |
| invitations | 4 | 4 |
| access requests | 5 | 5 |
| memberships | 5 | 5 |
| **total** | **41** | **39 (95%)** |

Uncovered: `POST /projects/{id}/environments/{envId}/clone` and `…/copy-secrets`,
the two bulk secret-copy operations. They are listed in `COVERAGE.md`.

### (3) Suspended-account and PAT-restricted principals

- **`suspended`:** `project_admin`@A, logged in, then suspended.
  - Both transports reject its credential (401 / `Unauthenticated`).
  - Core called directly does not check account state: new finding **D5**,
    62 cases across 19 ops. Added as design question 5.
- **`pat-restricted`:** a PAT owned by a `project_admin`@A user, allowed only
  `secrets.read` in project A.
  - The core leg mirrors the transports by attaching the restriction to ctx
    (`core.WithPATRestriction`).
  - REST, gRPC and core agree with the model on every PAT case once the
    documented rules are in. The rules are the allowlist and project scope
    on the permission check, and the restricted-PAT ungated-write table.
  - That refusal is REST-middleware-only (ADR-042, PAT-GUARD-3). Every op it
    covers is `core refusal = none`, so it never shows as a disagreement (no
    bucket needed).

**Not yet (deferred, not covered):**
- environment-scoped grants and environment-scoped PATs;
- MFA-required projects (step-up);
- PAT CIDR allowlists;
- SCIM-provisioned principals;
- impersonation sessions;
- break-glass activations.

### (4) The three plants as a permanent self-test

`plants_test.go` (`TestPlantsAreDetected`, opt-in `AUTHZDIFF_PLANTS=1`)
applies each plant with `go test -overlay`. The working tree is never edited;
the overlay swaps in a patched copy of the file at compile time. Each plant
is an exact anchor/replacement, and the anchor must occur exactly once, or
the test fails with "plant anchor drifted". So a refactor that moves the
guarded code forces the plant to be re-pointed; it is never skipped.

For each plant, a child sweep restricted to the planted op must produce:

- at least `minUnexplained` unexplained cases;
- all of them on that op;
- and zero unexplained cases in the same restricted sweep without the
  overlay.

**CI:** new job `authzdiff-plants` in `.github/workflows/ci.yml`, gated like
`closures-pg` (merge queue, push, schedule, dispatch, or `ci:full`). Locally
`actionlint` is clean. The job has not run in CI yet.

### Run evidence

| Run | Result |
|---|---|
| Default `go test ./server/authzdiff/` | PASS in **7.4 s** (two samples, idle machine), under the 10 s budget. Includes smoke over 48 ops, the coverage freshness check, the route binding check and the universe check. |
| Full STRICT sweep | 41,558 cases, PASS, **zero unexplained**, 7.4 min (`spawn.sh`, default parallelism) |
| Plant self-test (`AUTHZDIFF_PLANTS=1`) | PASS in 158 s. name-based-role-check: 670 unexplained cases, all on `machine.role.assign`. grpc-guard-removed: 239, all on `machine.token.revoke`. router-gate-removed: **26**, all on `group.delete` (Phase 3: 1). Each control run without the overlay: 0. |
| Self-test red check | With plant 3's replacement set to its own anchor (a no-op), the test fails: "0 unexplained cases on group.delete, want >= 10 — the harness stopped detecting it". Then reverted. |

**Uncalibrated legs.** All have by-design causes:
- `group.role.assign` at global scope with a project-tier role (role-scope
  rule, 400): 826 cases.
- `secret.share` on the viewer-owned s1. The owner lacks `secrets.write` at
  the route gate, so nobody can share it: 254 cases.
- None come from the 20 new ops.

**A harness bug found and fixed on the way.** The first three full Phase 4
sweeps were killed 2–3 minutes in. The cause: every test leg registered a
`tb.Cleanup` fallback, which kept the whole leg (router, core, DB handle)
reachable until its parallel op subtest ended, about 0.3 MB per REST leg.
Measured: +61 MB over 200 REST legs before the fix, +0 after.

- Legs now own their directory and are closed explicitly when their case
  ends.
- Earlier per-subtest temp directories from the killed runs (up to 1.3 GB
  each) are left in `$TMPDIR` as `TestAuthzDiffSweep*`; deleting them was
  not permitted from this session.

### Partition of the full Phase 4 sweep (41,558 cases)

| Bucket | Cases | Where |
|---|---|---|
| D1 gRPC group ops skip `users.read` | 130 | group create/update/delete/member-remove/**restore** (26 each) |
| D2 core looser than every transport | 1,797 | autorotate 955, member.setrole 239, group.restore 172, group.role.assign 158, invitation.global 131, project.restore 123, group.member.add 12, bulk approve 7 |
| D3 `IssueMachineToken` treats a machine as user 0 | 2 | machine.token.issue |
| D4 ownership grant unreachable | 2 | secret update/delete on s1 |
| **D5 (new) core ignores account state** | 62 | 19 ops |
| **D6 (new) machine actor never passes the ceiling** | 14 | member.add 8, member.setrole 6 (`AddProjectMember`/`SetProjectMemberRole` never tag `WithSelfMachineGranter`) |
| M1 REST 500/400 for a typed refusal | 5,761 | accessrequest.approve, invitation.create, machine.role.assign, member.add, membership.invite (1,150 each), env.restore 11 |
| M2 machine actor reaches a user-only core method | 274 | secret.share 210, accessrequest.create 56, secret.acl.grant 8 |
| M3 untyped core refusal | 492 | machine.oidc.create 252 (errAdminAuthorityRequired, answered **400** because its text contains "required"), membership.transition 240 |
| unexplained | **0** | |

**Rules generalized from op lists to outcome shapes** in Phase 4: D2, M1 and
M3 (D1 only gained `group.restore`). The generalization keeps the
bypass-relevant direction closed:

- D2 needs every present transport to deny;
- M1 and M3 need a refusal on some layer and the model to deny;
- D1 stays group-only and REST-deny/gRPC-allow.

The three plants are exactly the excluded shapes, and the self-test proves
it.

### Defect follow-up list (updated)

New items:

8. `AddProjectMember` / `SetProjectMemberRole` refuse every machine actor (D6).
9. Core ignores account state (D5). This is a design question, not a defect
   by itself; see design question 5.

Root cause (3) now also covers:
- M1 on `member.add`, `membership.invite` and `env.restore`;
- M3 on `machine.oidc.create`. The untyped `errAdminAuthorityRequired`
  reaches the client as **400**: a third wrong status for one root cause.
