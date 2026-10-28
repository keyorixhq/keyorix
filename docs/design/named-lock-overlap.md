# Named-lock sections against the lock-loss overlap window

Status: every inventoried site closed (NAMEDLOCK-OVERLAP-1, 2026-10-27: audit and
the user-deactivation family; NAMEDLOCK-OVERLAP-2, 2026-10-28: `LockNamedKeyInTx`
and every remaining family). Follows [pooler-lock-loss.md](pooler-lock-loss.md)
(POOLER-LOCKLOSS-1, #3622), whose "Not changed" section leaves this open:
"Named-lock sections should each re-check their precondition inside their write
transaction or rely on a constraint; this note does not audit them one by one."
This note does.

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
  every row the verdict rests on (`RemoveGlobalAdminRoleGuarded`, ...).
- **Conditional write**: an `UPDATE ... WHERE <expected state>` whose zero-row
  result is an error (state CAS).
- **Row-lock fence plus in-transaction re-check**: the write transaction first locks
  rows that every competing writer also locks (`SELECT ... FOR UPDATE`), then re-runs
  the check through `tx`. On PostgreSQL the second writer waits on the first's row
  locks, and its re-check runs after the first commit (READ COMMITTED takes a new
  snapshot per statement), so it sees the first one's write and refuses.
- **Named-key fence plus in-transaction re-check**: the same, where no row exists
  that every competing writer could lock: the write transaction first takes the
  section's own key with `LockNamedKeyInTx` (below), which every competing writer's
  transaction also takes.
- **In-transaction re-check without a lock**: narrows the window to the
  re-check-to-commit gap but does not close it (two such transactions open at once
  both see the pre-write state). Not counted as safe below.

SQLite has no overlap: its named lock is an in-process mutex and SQLite runs single
process, so every verdict below is about PostgreSQL.

## `LockNamedKeyInTx`

`Storage.LockNamedKeyInTx(ctx, key)` (`internal/storage/store/local_named_lock_tx.go`,
INV-STORE-named-key-tx-lock) is option E of pooler-lock-loss.md applied to the write
half of a section: `pg_advisory_xact_lock` taken inside the write transaction and
released by PostgreSQL when it ends, so it cannot outlive the write it fences. The
session lock keeps serializing the reads before the transaction.

- It hashes the key exactly as `WithNamedLock` does (FNV-1a) but takes the
  two-int4 advisory key space, which does not overlap the one-bigint space of the
  session lock. It must not: the holder's session lock is on a lock-pool connection
  and its transaction on a request-pool connection, another backend, so on one
  shared key every holder's transaction would wait on its own session lock forever
  (`TestNamedLockXactKey_Postgres_SharedBigintKeyWouldSelfDeadlock` shows it does).
- It refuses on a handle that is not a transaction (it would lock nothing).
- On SQLite it takes nothing: write transactions are already serialized there.

## The in-transaction fence (`txFence`)

Every family below closes the same way (`internal/core/named_lock_fence.go`): the
helper that owns a section's named lock hands its writer a `txFence`, which the writer
runs as the **first statement of its write transaction**; the fence takes the locks
every competing writer's transaction also takes, then re-runs the section's own
check through `tx`, on the same inputs. A fence never adds a refusal: the check is
the one the section already ran before its transaction.

Lock order inside a transaction, the same in every fence so two fenced transactions
cannot wait on each other in a cycle: named keys first (`LockNamedKeyInTx`, in
`storage.NamedLockOrder`, which `lockNamedKeysInTxOn` enforces), then rows: global
admin-tier grant rows, then user rows in ascending ID (the order #3753's
deactivation fence and `RemoveGlobalAdminRoleGuarded` already use).

## Inventory

How the list was built: every `WithNamedLock(` call in non-test `internal/core/*.go`
(the scan `TestNamedLockOverlap_EveryCallSiteIsInventoried` repeats, see "Guard"),
38 sites in 17 files on main at 24bcd85aa, unchanged since. Call sites in
`internal/storage/store` (the `DeleteEnvironment` and `RestoreSecret` storage halves)
are reached only inside core's fenced transactions, which take the key first
(environment secret guard, below).

Verdicts: **safe** (a constraint, fused call or conditional write keeps the invariant
on its own), **fixed** (a fence in the write transaction keeps it; NAMEDLOCK-OVERLAP-1
or -2).

The first three columns are read by the guard test: file, enclosing function, and
the lock-key expression exactly as written at the call site.

| File | Function | Key | Invariant (shape) | What holds in the write transaction | Verdict |
|---|---|---|---|---|---|
| internal/core/account_state.go | SuspendUser | lastAdminGuardLockKey | at least one usable global admin (count-then-deactivate) | grant-row fence + re-check (`fenceLastAdminDeactivationOn`) | fixed (-1) |
| internal/core/users.go | UpdateUser | lastAdminGuardLockKey | as above | grant-row fence + re-check; deactivating write is also a CAS on `is_active` | fixed (-1) |
| internal/core/users.go | DeleteUser | lastAdminGuardLockKey | as above | grant-row fence + re-check | fixed (-1) |
| internal/core/scim.go | UpdateSCIMUser | lastAdminGuardLockKey | as above | grant-row fence + re-check when `active=false` | fixed (-1) |
| internal/core/scim.go | DeprovisionSCIMUser | lastAdminGuardLockKey | as above | grant-row fence + re-check | fixed (-1) |
| internal/core/migrate_user_to_machine.go | MigrateUserToMachine | lastAdminGuardLockKey | as above (the source user is suspended) | grant-row fence + re-check | fixed (-1) |
| internal/core/rbac_management.go | removeGlobalAdminRoleIfApplicable | lastAdminGuardLockKey | as above (global admin grant removal) | fused `RemoveGlobalAdminRoleGuarded`: grant rows and holder rows FOR UPDATE | safe |
| internal/core/role_set_replace.go | narrowUserRoleSet | lastAdminGuardLockKey | as above (global branch of SetUserRoles) | fused `RemoveGlobalAdminRoleGuarded` per admin role (`applyRoleSetOn`) | safe |
| internal/core/rbac_management.go | withGroupRoleRemovalGuards | lastAdminGuardLockKey | as above (group role removal, global scope) | grant-row fence + `guardLastGlobalAdminGroupRoleOn(tx)` | fixed (-2) |
| internal/core/project_members.go | withGroupProjectAdminGuardLocks | lastAdminGuardLockKey | as above, plus last project admin of every project the group administers (DeleteGroup, RemoveUserFromGroup, SCIM group patch/replace/deprovision) | project keys (`LockNamedKeyInTx`), grant-row fence, then the caller's own guards through tx | fixed (-2) |
| internal/core/project_members.go | lockProjectAdminGuardsInOrder | projectAdminGuardLockKey(projectIDs[0]) | last project roles.assign holder (helper of the row above) | the row above's fence takes every one of these keys in the same ascending order | fixed (-2) |
| internal/core/project_members.go | RemoveProjectMember | projectAdminGuardLockKey(projectID) | last project roles.assign holder (count-then-delete) | `projectAdminRemovalFence`: the project key, then `guardLastProjectAdminOn(tx)` on the roles tx reads | fixed (-2) |
| internal/core/rbac_management.go | withUserRoleRemovalGuards | projectAdminGuardLockKey(scope.ProjectID) | as above (RemoveUserRole at project scope, access-review revoke) | `projectAdminRemovalFence` | fixed (-2) |
| internal/core/rbac_management.go | withGroupRoleRemovalGuards | projectAdminGuardLockKey(scope.ProjectID) | as above (group role removal at project scope) | the project key, then `guardLastProjectAdminGroupRoleOn(tx)` | fixed (-2) |
| internal/core/role_set_replace.go | narrowUserRoleSet | projectAdminGuardLockKey(r.scope.ProjectID) | as above (SetUserRoles / SetProjectMemberRole at project scope, incl. the one-transaction admin swap) | `projectAdminRemovalFence` on what the removals (or the swap) leave | fixed (-2) |
| internal/core/break_glass.go | RevokeBreakGlassActivationAtomic | projectAdminGuardLockKey(scope.ProjectID) | (1) a revoked activation keeps no grant (2) last project admin | (1) role removal and the conditional `RevokeBreakGlassActivation` commit together; (2) `projectAdminRemovalFence` | safe (1), fixed (-2) (2) |
| internal/core/break_glass.go | ActivateBreakGlass | projectAdminGuardLockKey(projectID) | a revoke never leaves the grant behind (#2722) | the record insert and the grant commit in one transaction; one active activation per (project, user) by unique index | safe |
| internal/core/rbac_management.go | assignUserRole | sodGrantLockKey("user", userID) | no separation-of-duties violation for the user (check-then-insert); backs AssignUserRole and AddProjectMember (membership activation passes its fence first) | `sodUserGrantFence`: the user's row FOR UPDATE, then `requireNoSoDViolationOn(tx)` | fixed (-2) |
| internal/core/rbac_management.go | assignUserRoleSystemGrant | sodGrantLockKey("user", userID) | as above (SSO reconcile) | as above | fixed (-2) |
| internal/core/rbac_management.go | grantBaselineRoleBackfill | sodGrantLockKey("user", userID) | as above (baseline backfill) | as above | fixed (-2) |
| internal/core/jit_access.go | AssignUserRoleWithExpiry | sodGrantLockKey("user", userID) | as above (JIT grant) | as above (break-glass, which skips the check by design, gets no fence) | fixed (-2) |
| internal/core/invitations.go | finalizeAccessRequestApproval | sodGrantLockKey("user", req.UserID) | as above (access-request grant) | as above; the request update is also conditional | fixed (-2) |
| internal/core/groups.go | AddUserToGroup | sodGrantLockKey("user", userID) | no SoD violation through the joined group's roles | the user's row, then `requireGroupJoinNoSoDViolationOn(tx)` on the grants tx reads (when the check ran) | fixed (-2) |
| internal/core/role_set_replace.go | replaceUserRoleSet | sodGrantLockKey("user", r.userID) | no SoD violation for the new set | the user's row, then `applyRoleSetOn`'s own in-tx re-check | fixed (-2) |
| internal/core/role_set_replace.go | swapUserRoleSet | sodGrantLockKey("user", r.userID) | as above | the project key and last-admin re-check, the user's row, then the in-tx re-check | fixed (-2) |
| internal/core/rbac_management.go | withOrderedUserSoDLocks | sodGrantLockKey("user", ids[0]) | every member's SoD for a group grant (helper) | `sodGroupGrantFence`: every active member's row in the same ascending order, then the group check through tx | fixed (-2) |
| internal/core/rbac_management.go | AssignRoleToGroup | sodGrantLockKey("group", groupID) | no SoD violation for any member (check-then-insert) | the group key (`sodGroupKeyFence`), then `sodGroupGrantFence` | fixed (-2) |
| internal/core/jit_access.go | AssignGroupRoleWithExpiry | sodGrantLockKey("group", groupID) | as above (JIT group grant) | as above | fixed (-2) |
| internal/core/groups.go | RestoreGroup | sodGrantLockKey("group", id) | only a global admin restores a group carrying admin roles (read-then-restore, #2455) | the group key (`LockNamedKeyInTx`), then the ceiling check on the roles tx reads | fixed (-2) |
| internal/core/machine_token.go | AssignMachineRole | sodGrantLockKey("machine", machineID) | no SoD violation for the machine (check-then-insert) | the machine's row FOR UPDATE, then `requireMachineGrantNoSoDViolationOn(tx)` | fixed (-2) |
| internal/core/machine_token.go | withMachineRoleRemovalGuards | sodGrantLockKey("machine", machineID) | none that overlap can break: a removal plus an environment-in-project scope check | removal only | safe |
| internal/core/membership_lifecycle.go | inviteMemberWithMode | membershipLockKey(projectID, userID) | (1) one active onboarding per (project, user) (2) no grant on a revoked membership (#2659) | (1) partial unique index `uniq_project_memberships_active`; (2) `membershipActiveFence` in the grant's transaction | safe (1), fixed (-2) (2) |
| internal/core/membership_lifecycle.go | TransitionMembership | membershipLockKey(m.ProjectID, m.UserID) | no grant on a revoked membership (#2657) | the state CAS takes the membership key in its transaction; the activation grant's transaction takes it and re-reads the state (`membershipActiveFence`) | fixed (-2) |
| internal/core/invitations.go | ApproveAccessRequestWithExpiry | dualControlLockKey(requestID) | the K-th approval grants (M-of-K) | role grant by primary key, one approval per approver by unique index, conditional request update: an overlap fails closed (the request stays pending) | safe |
| internal/core/secret_dependencies.go | LockedCreateSecretDependencyExclusive | secretDependencyGraphLockKey(d.ProjectID) | the project's dependency graph stays acyclic (read-graph-then-insert) | the graph key (`LockNamedKeyInTx`), then the fused `CreateSecretDependencyExclusive` as a savepoint | fixed (-2) |
| internal/core/secrets.go | withEnvironmentSecretGuard | storage.EnvironmentSecretGuardLockKey(environmentID) | no secret or folder created in, or resumed into, a deleted environment (check-then-insert) | the environment key, then the existence check through tx | fixed (-2) |
| internal/core/secrets.go | RestoreSecret | storage.EnvironmentSecretGuardLockKey(secret.EnvironmentID) | as above (restore) | the environment key, then the storage restore's `requireLiveEnvironment` through tx | fixed (-2) |
| internal/core/catalog.go | DeleteEnvironment | storage.EnvironmentSecretGuardLockKey(id) | no active secret left in a deleted environment (count-then-delete) | the environment key, then the storage count and delete through tx | fixed (-2) |

Totals: 38 sites. 31 fixed (6 by NAMEDLOCK-OVERLAP-1, 25 by NAMEDLOCK-OVERLAP-2);
5 safe; 2 with two invariants, each now kept (`RevokeBreakGlassActivationAtomic`,
`inviteMemberWithMode`: safe for the first, fixed for the second). None needs a
check, none waits on a decision.

## Fixed by NAMEDLOCK-OVERLAP-1: user deactivation (6 sites)

`fenceLastAdminDeactivationOn` (`internal/core/last_admin_fence.go`) is the first
statement of each deactivating write transaction. For a target that holds a global
admin-tier role it row-locks every global admin-tier grant
(`ListGlobalAdminAssignmentsForUpdate`) and re-runs `guardLastAdminDeactivation`
through `tx`. `RemoveGlobalAdminRoleGuarded` locks the same rows in the same order
(grants, then users), so a deactivation and a grant removal also wait on each other
and cannot deadlock. The group-path writers lock the same rows since
NAMEDLOCK-OVERLAP-2, which closes the residual #3753 left (a deactivation
overlapping a group-membership or group-role removal).

Tests: `TestNamedLockOverlap_UserDeactivation_LastAdminSurvives` (SQLite, one case
per path) and `TestNamedLockOverlap_SuspendUser_ConcurrentWriteTransactions_Postgres`.

## Fixed by NAMEDLOCK-OVERLAP-2

Each family's tests: one SQLite test on the fake lock backend of
`internal/core/named_lock_overlap_harness_test.go` (holder B runs its whole operation
at holder A's first write transaction under the key; A must then be refused), and one
pg-gated test with both write transactions open at once (`overlapPGRun`: replica A's
named lock is real but takes its sessions in another database, the state after a
loss; replica B starts from inside A's write transaction, after A's fence, and must
wait for A, then be refused). Every test below was red on the tree before its family's
commit and is green after it (session report: redproof output).

- **Group-path last admin** (`withGroupProjectAdminGuardLocks`, `lockProjectAdminGuardsInOrder`,
  `withGroupRoleRemovalGuards`): the project keys the section holds, the global
  admin-tier grant rows, then the caller's guards (`guardLastGlobalAdminGroup*On`,
  `guardLastProjectAdminGroup*On`) through tx. `RevokeAccessReviewGrant` wrote its
  removal outside any transaction; it now removes through `runOwedAuditMutation`.
  Tests: `TestNamedLockOverlap_GroupPath_LastAdminSurvives` (RemoveUserFromGroup,
  RemoveRoleFromGroup, DeleteGroup, DeprovisionSCIMGroup, PatchSCIMGroup,
  ReplaceSCIMGroup, RevokeAccessReviewGrant; global and project),
  `TestNamedLockOverlap_RemoveUserFromGroup_ConcurrentWriteTransactions_Postgres`,
  `TestNamedLockOverlap_RemoveRoleFromGroupProject_ConcurrentWriteTransactions_Postgres`.
- **SoD, user and machine principals**: the principal's row (`LockUserForUpdate`,
  `LockMachineIdentityForUpdate`), then the same separation-of-duties check through
  tx. `grantUserRoleAudited` takes the fence as a parameter, so break-glass (which
  skips the check by design) gets none. Tests:
  `TestNamedLockOverlap_SoD_UserAndMachine_NoToxicPair`,
  `TestNamedLockOverlap_SoD_ConcurrentWriteTransactions_Postgres`. SetUserRoles
  already re-checked in its transaction without a lock: its overlap is red only on
  PostgreSQL.
- **SoD, group principals**: every active member's row in ascending ID order (the
  order `withGroupMemberSoDLocks` named-locks them), then the group check through tx
  on the same snapshot. Tests: `TestNamedLockOverlap_SoD_GroupGrant_NoToxicPair`,
  `TestNamedLockOverlap_SoDGroupGrant_ConcurrentWriteTransactions_Postgres`.
- **Membership**: the activation grant's transaction takes the membership key and
  re-reads the membership, rolling back unless it is still active; the state CAS
  takes the same key in its transaction, so a revoke cannot commit between that
  re-read and the grant. Tests: `TestNamedLockOverlap_Membership_NoGrantOnRevoked`,
  `TestNamedLockOverlap_MembershipActivation_ConcurrentWriteTransactions_Postgres`.
- **Last project admin**: `projectAdminRemovalFence` in RemoveProjectMember,
  RemoveUserRole and the access-review user revoke at project scope, SetUserRoles /
  SetProjectMemberRole (and the swap) and RevokeBreakGlassActivationAtomic. Tests:
  `TestNamedLockOverlap_ProjectAdmin_LastAdminSurvives`,
  `TestNamedLockOverlap_ProjectAdmin_ConcurrentWriteTransactions_Postgres`.
- **Secret dependency graph**: the graph key, then the fused insert. PostgreSQL only
  (on SQLite the fused call already reads the other insert's committed edge). Tests:
  `TestNamedLockOverlap_SecretDependency_LostLocksRace_Postgres` (40 trials of two
  lost-lock replicas adding opposite edges: every trial committed a cycle before the
  fix, none after) and `TestNamedLockOverlap_SecretDependency_ConcurrentWriteTransactions_Postgres`.
- **Environment secret guard**: the environment key, then the existence check
  (create, folder, resume, restore) or the count (delete) through tx. Tests:
  `TestNamedLockOverlap_EnvironmentSecretGuard_NoActiveSecretInDeletedEnvironment`,
  `TestNamedLockOverlap_EnvironmentSecretGuard_ConcurrentWriteTransactions_Postgres`,
  `TestNamedLockOverlap_RestoreSecretVsDeleteEnvironment_LostLocksRace_Postgres`
  (RestoreSecret already re-checked in its transaction without a lock; its overlap
  window is a few statements wide, hit in 6 of 150 trials before the fix, none after).
- **RestoreGroup**: the group key, then the ceiling check on the roles tx reads;
  every grant to a group takes the same key first (`sodGroupKeyFence`). Tests:
  `TestNamedLockOverlap_RestoreGroup_CeilingSeesConcurrentAdminGrant`,
  `TestNamedLockOverlap_RestoreGroup_ConcurrentWriteTransactions_Postgres`.

## Not fixed

Nothing in the inventory. One finding outside it remains (next section).

## Found along the way (not an overlap issue)

`AddUserToGroup` takes `sodGrantLockKey("user", userID)` only, and
`AssignRoleToGroup` takes `sodGrantLockKey("group", groupID)` plus the locks of the
group's *current* members. A user joining the group while a role is granted to it
shares no key with the grant: the grant's SoD check does not see the joining member,
the join's check does not see the new role, and both commit even with every lock
held. Not changed by either session; it needs the grant's in-transaction check to
re-list the members under a key the join also takes. Its own fix(security) PR.

## Guard

`TestNamedLockOverlap_EveryCallSiteIsInventoried` (`internal/core/guards`) parses
every non-test `internal/core/*.go`, lists each `WithNamedLock` call as (file,
enclosing function, key expression), and fails when a call has no row in the table
above, or a row names no call. A new named-lock section therefore cannot land without
someone writing down what it protects and whether the overlap can break it. It checks
that a row exists, not that its verdict is right; the per-family tests above are what
check the fences.
