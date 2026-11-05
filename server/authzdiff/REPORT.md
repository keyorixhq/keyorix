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
- secret ops: update, delete, ACL grant/revoke, auto-rotate, share,
  value read by ref, value read by id;
- groups: create/update/delete, member add/remove, role assign/remove;
- projects: create/update/delete;
- machine identities: create, token issue/revoke, transition, role assign;
- invitations: create/revoke;
- access requests: approve/reject;
- memberships: transition.


## Phase 3: prove it fires

### Method

1. Commit a clean baseline: a STRICT sweep of 4,572 cases with zero
   unexplained. Every flagged case is assigned to a known waiver by `explain()`.
2. Plant one defect in production code.
3. Re-run the full STRICT sweep. A planted defect matches no known waiver's
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
- **Oracle 2 caught the planted defect end to end**: 8 cases where core *and*
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
  untyped.

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
- The final STRICT run passes: 4,572 cases, unexplained 0.
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
globally") is now generated 26 times. That is the shape plant 3 needs. In Phase 3 it was
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

- **`suspended`:** `project_admin`@A, logged in, then suspended. The model
  denies a suspended account everything.
- **`pat-restricted`:** a PAT owned by a `project_admin`@A user, allowed only
  `secrets.read` in project A.
  - The core leg mirrors the transports by attaching the restriction to ctx
    (`core.WithPATRestriction`).
  - The model applies the documented rules: the allowlist and project scope
    on the permission check, and the restricted-PAT ungated-write table
    (ADR-042, PAT-GUARD-3).

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

**CI:** new job `authzdiff-plants` in `.github/workflows/ci.yml`. It runs only
on the nightly schedule, on manual dispatch and on PRs labelled `ci:full`. It
never runs in the merge queue or on push: merge-queue time is tightly managed,
and the self-test takes ~3 min. Locally `actionlint` is clean.

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
- `secret.share` on the viewer-owned s1 (owner rule, not modelled): 254 cases.
- None come from the 20 new ops.

**A harness memory issue fixed on the way.** The first three full Phase 4
sweeps were killed 2–3 minutes in. The cause: every test leg registered a
`tb.Cleanup` fallback, which kept the whole leg (router, core, DB handle)
reachable until its parallel op subtest ended, about 0.3 MB per REST leg.
Measured: +61 MB over 200 REST legs before the fix, +0 after.

- Legs now own their directory and are closed explicitly when their case
  ends.
- Earlier per-subtest temp directories from the killed runs (up to 1.3 GB
  each) are left in `$TMPDIR` as `TestAuthzDiffSweep*`; deleting them was
  not permitted from this session.


**Test placement.**

| Test | When it runs | Time |
|---|---|---|
| Default `go test ./server/authzdiff/` | normal CI test leg `root-4` | 7.6 s (8.4 s at load average ~6.9) |
| `TestAuthzDiffSweep` | opt-in `AUTHZDIFF_SWEEP=1` | ~8 min |
| `TestPlantsAreDetected` | opt-in `AUTHZDIFF_PLANTS=1`; CI job `authzdiff-plants` (nightly, dispatch, `ci:full`) | ~3 min |

```
AUTHZDIFF_PLANTS=1 GOFLAGS= go test ./server/authzdiff/ -run '^TestPlantsAreDetected$' -count=1 -timeout 60m -v
```

**Lint.** golangci-lint v2.14.0 (the CI-pinned version) on
`./server/authzdiff/...` and `./devtools/authzmatrix/...`: 0 issues.


## Phase 5: secret and users/roles operations

### Fixtures added (synthetic, per project A and B unless noted)

- A certificate-type secret (a self-signed PEM generated at seed time, valid
  2000–2099, never stored in the tree).
- Secrets that are soft-deleted, suspended, two-version (with a comment on
  version 1), expiring in 10 days, and plain.
- A folder, a dependency edge (cert → two-version), a share record
  (two-version → the ACL recipient, read) and a live empty environment
  `staging2`.
- Install-wide: an active user holding only the CreateUser baseline
  (`system_viewer`@global), a soft-deleted user, and a custom role `ops-role`
  (project scope, `secrets.read`).

### Operations added

- **23 secret ops:**
  - create; description; tags; retention.
  - share revoke and update; self-share remove.
  - dependency add and remove; version comment add and delete.
  - certificate; restore; suspend; resume; rollback; rotate; rotation simulate.
  - copy; move; extend-expiring; environment clone; environment copy-secrets.
- **20 users/roles ops:**
  - user create (plain, and with a project assignment); update; delete; restore.
  - suspend; reactivate; require-reset; revoke-sessions; resend-setup;
    reissue-OTP; unlock.
  - set user roles; user-role assign and remove.
  - role create, update and delete; role permission add and remove.
- **Model additions:**
  - A recipient-only rule (self-share removal: no permission involved).
  - The users-route rank ceiling, modelled as the target's
    `system_viewer`@global permissions. Unlock is deliberately not
    ceiling-gated (`login_lockout.go`).
- `/users` routes go through the package-level `defaultUserHandler`. The REST
  leg re-points it under `routerMu` (`opSpec.globalHandler`).

### Coverage (generated, `COVERAGE-ALL.md`)

| family | REST in scope | REST covered | gRPC in scope | gRPC covered |
|---|---|---|---|---|
| groups | 8 | 8 | 6 | 6 |
| projects | 8 | **8** | 3 | 3 |
| machine identities | 11 | 11 | 6 | 6 |
| invitations | 4 | 4 | 0 | 0 |
| access requests | 5 | 5 | 0 | 0 |
| memberships | 5 | 5 | 0 | 0 |
| secrets | 43 | **29** | 10 | **10** |
| other | 127 | **19** | 21 | **9** |
| **total** | **211** | **89** | **46** | **34** |

- The "other" gains are users/roles, which is now complete: REST 19/19, gRPC 9/9.
  - The `/scim/v2/Users` routes are out of scope here; SCIM principals stay on
    the not-yet list.
- 134 uncovered ops remain, each with a reason: 59 design, 48 fixture, 27 model.
  - Secrets still uncovered: the bulk operations (design); schedule and
    classification (model); render (fixture); transfer-ownership (model:
    waits on an open design question).


### Full strict sweep

65,454 cases, 12.8 min, PASS, **0 unexplained**. Every flagged case is
assigned to a known waiver by an exact shape rule (`partition_test.go`).

### Default run and CI

- **Default `go test ./server/authzdiff/ ./devtools/authzmatrix/...`:** PASS in
  **3.2 s**. With 43 more ops it had grown to 12.4 s. Three changes brought it
  down:
  - smoke subtests now run in parallel, as the sweep's do;
  - the coverage probe reuses one gRPC leg;
  - `TestMain` lowers the bcrypt cost through core's documented
    `SetBcryptCostForTesting` hook, which removed ~4.8 s of the 4.9 s seed.
- **golangci-lint v2.14.0** on both paths: 0 issues.
- **Repo guards for the new packages:**
  - `docs/state-map/stores.tsv` now registers `devtools/authzmatrix`'s file
    writes (the statemap completeness guard).
  - Review-coverage ledger fragments for the two new packages (depth `none`,
    `test-helper`).
- **Plant self-test** (`AUTHZDIFF_PLANTS=1`) after the waiver updates: PASS in 109 s, unchanged counts (670 / 239 / 26 unexplained, each only on its planted op; controls 0).

## Open items

Tracked privately.

