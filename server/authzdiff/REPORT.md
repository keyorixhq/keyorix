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

### Open decision for Phase 2

`errAdminAuthorityRequired` is unexported, so a harness outside
`internal/core` can only classify it by message text, which is forbidden.
Options:

- (a) Add a one-line exported alias, or wrap it with
  `markPermissionDenied`. Both are production changes, and the second is
  arguably the fix itself.
- (b) Leave it as `other` and let these pairs land in the mapping-gap
  bucket. This is the default if no answer.
