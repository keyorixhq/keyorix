# Named-lock sections against the lock-loss overlap window

Status: audit and partial fix (NAMEDLOCK-OVERLAP-1, 2026-10-27). Follows
[pooler-lock-loss.md](pooler-lock-loss.md) (POOLER-LOCKLOSS-1, #3622), whose "Not
changed" section leaves this open: "Named-lock sections should each re-check their
precondition inside their write transaction or rely on a constraint; this note does
not audit them one by one." This note does.

## The window

`WithNamedLock` holds a PostgreSQL advisory lock on its own connection. When that
connection dies (backend terminated, failover, pooler timeout), PostgreSQL releases
the lock at once, but the holder learns of it only at the next liveness ping: up to
one interval plus the ping timeout (5 s + 5 s by default). Then the holder's ctx is
cancelled with `ErrAdvisoryLockLost`. Inside the window, a second replica can take
the same key and run the same section.

What the window can break: a section that **checks** something, then **writes** in a
later transaction. If the first holder's check ran before the loss and its write
commits inside the window, and the second holder checked before that commit, both
act on a state the other changes. A write transaction still open when the ctx is
cancelled rolls back, so only commits inside the window matter.

What keeps an invariant despite the window, strongest first:

- **Constraint**: a unique index or a primary key makes the second insert fail.
- **Fused storage call**: check and write in one storage transaction that row-locks
  every row the verdict rests on (`RemoveGlobalAdminRoleGuarded`,
  `CreateSecretDependencyExclusive`, ...).
- **Conditional write**: an `UPDATE ... WHERE <expected state>` whose zero-row
  result is an error (state CAS).
- **Row-lock fence plus in-transaction re-check**: the write transaction first locks
  rows that every competing writer also locks (`SELECT ... FOR UPDATE`), then re-runs
  the check through `tx`. On PostgreSQL the second writer waits on the first's row
  locks, and its re-check runs after the first commit (READ COMMITTED takes a new
  snapshot per statement), so it sees the first one's write and refuses.
- **In-transaction re-check without a row lock**: narrows the window to the
  re-check-to-commit gap but does not close it (two such transactions open at once
  both see the pre-write state). Not counted as safe below.

SQLite has no overlap: its named lock is an in-process mutex and SQLite runs single
process, so every verdict below is about PostgreSQL.

## Inventory

How the list was built: every `WithNamedLock(` call in non-test `internal/core/*.go`
(the scan `TestNamedLockOverlap_EveryCallSiteIsInventoried` repeats, see "Guard"),
38 sites in 17 files on main at 24bcd85aa. Call sites in `internal/storage/store`
(`DeleteEnvironment`, `RestoreSecret` storage halves) are listed under the family
that uses them but are out of this audit's scope (no storage changes here).

Verdicts: **safe** (a mechanism in the list above keeps the invariant), **fixed**
(needed an in-transaction check; this PR adds it), **needs check** (needs an
in-transaction check, not added yet; see "Not fixed"), **NEEDS ANDREI** (cannot be
made safe without a schema change or a new storage method).

The first three columns are read by the guard test: file, enclosing function, and
the lock-key expression exactly as written at the call site.

| File | Function | Key | Invariant (shape) | What holds in the write transaction today | Verdict |
|---|---|---|---|---|---|
| internal/core/account_state.go | SuspendUser | lastAdminGuardLockKey | at least one usable global admin (count-then-deactivate) | fence + re-check (`fenceLastAdminDeactivationOn`) | fixed |
| internal/core/users.go | UpdateUser | lastAdminGuardLockKey | as above | fence + re-check; deactivating write is also a CAS on `is_active` | fixed |
| internal/core/users.go | DeleteUser | lastAdminGuardLockKey | as above | fence + re-check | fixed |
| internal/core/scim.go | UpdateSCIMUser | lastAdminGuardLockKey | as above | fence + re-check when `active=false` | fixed |
| internal/core/scim.go | DeprovisionSCIMUser | lastAdminGuardLockKey | as above | fence + re-check | fixed |
| internal/core/migrate_user_to_machine.go | MigrateUserToMachine | lastAdminGuardLockKey | as above (the source user is suspended) | fence + re-check | fixed |
| internal/core/rbac_management.go | removeGlobalAdminRoleIfApplicable | lastAdminGuardLockKey | as above (global admin grant removal) | fused `RemoveGlobalAdminRoleGuarded`: grant rows and holder rows FOR UPDATE | safe |
| internal/core/role_set_replace.go | narrowUserRoleSet | lastAdminGuardLockKey | as above (global branch of SetUserRoles) | fused `RemoveGlobalAdminRoleGuarded` per admin role (`applyRoleSetOn`) | safe |
| internal/core/rbac_management.go | withGroupRoleRemovalGuards | lastAdminGuardLockKey | as above (group role removal, global scope) | guard runs before the transaction, no re-check | needs check |
| internal/core/project_members.go | withGroupProjectAdminGuardLocks | lastAdminGuardLockKey | as above, plus last project admin of every project the group administers (DeleteGroup, RemoveUserFromGroup, SCIM group patch/deprovision) | guards run before the transaction, no re-check | needs check |
| internal/core/project_members.go | lockProjectAdminGuardsInOrder | projectAdminGuardLockKey(projectIDs[0]) | last project roles.assign holder (helper of the row above) | as above | needs check |
| internal/core/project_members.go | RemoveProjectMember | projectAdminGuardLockKey(projectID) | last project roles.assign holder (count-then-delete) | guard before the transaction | NEEDS ANDREI |
| internal/core/rbac_management.go | withUserRoleRemovalGuards | projectAdminGuardLockKey(scope.ProjectID) | as above (RemoveUserRole at project scope, access-review revoke) | guard before the transaction | NEEDS ANDREI |
| internal/core/rbac_management.go | withGroupRoleRemovalGuards | projectAdminGuardLockKey(scope.ProjectID) | as above (group role removal at project scope) | guard before the transaction | NEEDS ANDREI |
| internal/core/role_set_replace.go | narrowUserRoleSet | projectAdminGuardLockKey(r.scope.ProjectID) | as above (SetUserRoles at project scope) | guard before the transaction; the removal set is re-read in tx (`applyRoleSetOn`) but the guard is not | NEEDS ANDREI |
| internal/core/break_glass.go | RevokeBreakGlassActivationAtomic | projectAdminGuardLockKey(scope.ProjectID) | (1) a revoked activation keeps no grant (2) last project admin | (1) role removal and the conditional `RevokeBreakGlassActivation` commit together, and a revoke can only name a committed activation, whose grant committed with it; (2) guard before the transaction | safe for (1); (2) as RemoveProjectMember (a break-glass role is refused roles.assign at activation) |
| internal/core/break_glass.go | ActivateBreakGlass | projectAdminGuardLockKey(projectID) | a revoke never leaves the grant behind (#2722) | the record insert and the grant commit in one transaction; one active activation per (project, user) by unique index | safe |
| internal/core/rbac_management.go | AssignUserRole | sodGrantLockKey("user", userID) | no separation-of-duties violation for the user (check-then-insert) | SoD check before the transaction | needs check |
| internal/core/rbac_management.go | assignUserRoleSystemGrant | sodGrantLockKey("user", userID) | as above (SSO reconcile) | as above | needs check |
| internal/core/rbac_management.go | grantBaselineRoleBackfill | sodGrantLockKey("user", userID) | as above (baseline backfill) | as above | needs check |
| internal/core/jit_access.go | AssignUserRoleWithExpiry | sodGrantLockKey("user", userID) | as above (JIT grant) | as above | needs check |
| internal/core/invitations.go | finalizeAccessRequestApproval | sodGrantLockKey("user", req.UserID) | as above (access-request grant) | as above; the request update is conditional (`UpdateAccessRequest` ok=false refuses) | needs check |
| internal/core/groups.go | AddUserToGroup | sodGrantLockKey("user", userID) | no SoD violation through the joined group's roles | check before the transaction | needs check |
| internal/core/role_set_replace.go | replaceUserRoleSet | sodGrantLockKey("user", r.userID) | no SoD violation for the new set | `requireNoSoDViolationOn(tx)` re-check in the transaction, no row lock | needs check |
| internal/core/role_set_replace.go | swapUserRoleSet | sodGrantLockKey("user", r.userID) | as above | as above | needs check |
| internal/core/rbac_management.go | withOrderedUserSoDLocks | sodGrantLockKey("user", ids[0]) | every member's SoD for a group grant (helper) | check before the transaction | needs check |
| internal/core/rbac_management.go | AssignRoleToGroup | sodGrantLockKey("group", groupID) | no SoD violation for any member (check-then-insert) | check before the transaction | needs check |
| internal/core/jit_access.go | AssignGroupRoleWithExpiry | sodGrantLockKey("group", groupID) | as above (JIT group grant) | as above | needs check |
| internal/core/groups.go | RestoreGroup | sodGrantLockKey("group", id) | only a global admin restores a group carrying admin roles (read-then-restore, #2455) | ceiling check before the transaction | NEEDS ANDREI |
| internal/core/machine_token.go | AssignMachineRole | sodGrantLockKey("machine", machineID) | no SoD violation for the machine (check-then-insert) | check before the transaction | needs check |
| internal/core/machine_token.go | withMachineRoleRemovalGuards | sodGrantLockKey("machine", machineID) | none that overlap can break: a removal plus an environment-in-project scope check | removal only | safe |
| internal/core/membership_lifecycle.go | inviteMemberWithMode | membershipLockKey(projectID, userID) | (1) one active onboarding per (project, user) (2) no grant on a revoked membership (#2659) | (1) partial unique index `uniq_project_memberships_active`; (2) state read before the grant, no re-check | safe for (1); needs check for (2) |
| internal/core/membership_lifecycle.go | TransitionMembership | membershipLockKey(m.ProjectID, m.UserID) | no grant on a revoked membership (#2657) | state CAS, but the grant/removal side effect is not in the CAS's transaction | needs check |
| internal/core/invitations.go | ApproveAccessRequestWithExpiry | dualControlLockKey(requestID) | the K-th approval grants (M-of-K) | role grant by primary key, one approval per approver by unique index, conditional request update: an overlap fails closed (the request stays pending) | safe |
| internal/core/secret_dependencies.go | LockedCreateSecretDependencyExclusive | secretDependencyGraphLockKey(d.ProjectID) | the project's dependency graph stays acyclic (read-graph-then-insert) | fused `CreateSecretDependencyExclusive`, FOR UPDATE on existing edges; does not stop a phantom insert (an empty graph has nothing to lock, and a waiter's locked read keeps its old snapshot) | NEEDS ANDREI |
| internal/core/secrets.go | withEnvironmentSecretGuard | storage.EnvironmentSecretGuardLockKey(environmentID) | no secret or folder created in a deleted environment (check-then-insert) | environment liveness read before the write; project liveness (`LockLiveProject`) is re-checked, environment liveness is not | NEEDS ANDREI |
| internal/core/secrets.go | RestoreSecret | storage.EnvironmentSecretGuardLockKey(secret.EnvironmentID) | as above (restore) | as above | NEEDS ANDREI |
| internal/core/catalog.go | DeleteEnvironment | storage.EnvironmentSecretGuardLockKey(id) | no active secret left in a deleted environment (count-then-delete) | count and delete in the storage call, no row lock on the environment | NEEDS ANDREI |

Totals: 38 sites. 6 fixed here; 5 safe; 2 safe for one of their two invariants
only (`RevokeBreakGlassActivationAtomic`: its last-project-admin part is the
NEEDS ANDREI family; `inviteMemberWithMode`: its grant-on-revoked part needs a
check); 16 need an in-transaction check; 9 NEEDS ANDREI.

## Fixed here: user deactivation (6 sites)

`fenceLastAdminDeactivationOn` (`internal/core/last_admin_fence.go`) is the first
statement of each deactivating write transaction. For a target that holds a global
admin-tier role it row-locks every global admin-tier grant
(`ListGlobalAdminAssignmentsForUpdate`, an existing storage method) and re-runs
`guardLastAdminDeactivation` through `tx`. `RemoveGlobalAdminRoleGuarded` locks the
same rows in the same order (grants, then users), so a deactivation and a grant
removal also wait on each other and cannot deadlock. The guard before the
transaction stays as the ordinary refusal.

Tests:

- `TestNamedLockOverlap_UserDeactivation_LastAdminSurvives` (SQLite, default CI): the
  fake lock backend in `internal/core/named_lock_overlap_harness_test.go` grants
  holder A the key, then "loses" it at A's first transaction; holder B (a second
  `KeyorixCore` over the same database, as a second replica) deactivates the other
  admin and commits; A continues. One case per path (SuspendUser, UpdateUser,
  DeleteUser, UpdateSCIMUser, DeprovisionSCIMUser, MigrateUserToMachine). Red on main
  (both admins deactivated), green with the fence.
- `TestNamedLockOverlap_SuspendUser_ConcurrentWriteTransactions_Postgres` (pg-gated):
  two replicas with their own pools, B started from inside A's open write
  transaction. Red on main (B commits while A's transaction is open, both admins
  suspended), green with the fence (B waits on A's row locks, then is refused).

Residual: the family is closed only when every writer of it takes the fence. The
group-path last-admin writers (`withGroupRoleRemovalGuards` global branch,
`withGroupProjectAdminGuardLocks`) do not yet, so a deactivation can still overlap a
group-membership or group-role removal. Same fix, next step (see LEFTOVERS in the
session report).

## Not fixed, and why

**needs check** (16 sites, plus half of `inviteMemberWithMode`): an in-transaction re-check is possible with existing
storage methods, but it was not added in this PR (size; one caller group per PR
commit). The mechanism for each family:

- *Group-path last admin*: the same fence, with `guardLastGlobalAdminGroup*` run
  through `tx` (they already take the assignment list as data).
- *SoD, user and machine principals*: `LockUserForUpdate(userID)` /
  `LockMachineIdentityForUpdate(machineID)` first in the grant transaction, then
  `requireNoSoDViolationOn(tx)` (already exists, used by `applyRoleSetOn`). For a
  group grant, lock every member's user row in ascending ID order, the order
  `withGroupMemberSoDLocks` already uses for the named locks.
- *Membership*: re-read the membership state inside the grant's transaction after
  the grant, and roll back unless it is still the expected state.

**NEEDS ANDREI** (9 sites, plus half of `RevokeBreakGlassActivationAtomic`): no row exists that every competing writer could lock
without a new storage method:

- *Last project admin* (`projectAdminGuardLockKey`): the verdict rests on the
  project's roles.assign holders, users and groups. Locking every holder's user row
  works for user grants but not for a holder that becomes one through a group, and
  `LockLiveProject` is `FOR SHARE` (two writers do not exclude each other).
- *Secret dependency graph*: needs the cycle check to re-read after its row locks are
  granted (or a project-row `FOR UPDATE`) inside `CreateSecretDependencyExclusive`, a
  storage change.
- *Environment secret guard*: needs an environment-row lock in
  `LocalStorage.DeleteEnvironment` and a liveness re-read of the environment in the
  create/restore transactions (`LockLiveProject`'s environment counterpart), a
  storage change.
- *RestoreGroup*: the ceiling check reads the group's roles; a concurrent group-role
  grant inserts a row the restore cannot lock.

Recommendation for all of these, and for the "needs check" sites too: one storage
method, `LockNamedKeyInTx(ctx, key)` on the transaction handle, that takes
`pg_advisory_xact_lock` on the same key hash inside the write transaction (option E in
pooler-lock-loss.md, applied to the write half only). The session lock keeps
serializing the reads before the transaction; the transaction lock ends with the
writes, so it cannot outlive them, and each caller only has to move its check after
it inside the transaction. That is a storage-interface change, out of this session's
scope (no storage methods), so it is asked, not done.

## Found along the way (not an overlap issue)

`AddUserToGroup` takes `sodGrantLockKey("user", userID)` only, and
`AssignRoleToGroup` takes `sodGrantLockKey("group", groupID)` plus the locks of the
group's *current* members. A user joining the group while a role is granted to it
shares no key with the grant: the grant's SoD check does not see the joining member,
the join's check does not see the new role, and both commit even with every lock
held. Reported in the session report for its own fix(security) PR; not changed here.

## Guard

`TestNamedLockOverlap_EveryCallSiteIsInventoried` (`internal/core/guards`) parses
every non-test `internal/core/*.go`, lists each `WithNamedLock` call as (file,
enclosing function, key expression), and fails when a call has no row in the table
above, or a row names no call. A new named-lock section therefore cannot land without
someone writing down what it protects and whether the overlap can break it.
