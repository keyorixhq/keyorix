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
