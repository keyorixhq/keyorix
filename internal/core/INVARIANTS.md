# internal/core invariants

Read this before changing anything in `internal/core`. These are rules repeated bugs and ADRs
have forced onto this package; each one links to what enforces it today, or is marked
UNGUARDED with a filed issue. `internal/core` is the single place business logic lives — HTTP,
gRPC and CLI are all callers of it, never reimplementers of it.

Format: `INV-CORE-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## Authorization ceiling

- **INV-CORE-01** Every per-actor authorization ceiling derives from the ACTOR's own effective
  privileges, never only the target's — a ceiling that inspects only the target lets a
  zero-standing attacker self-mint into an empty/attacker-controlled target. Why: CLAUDE.md
  "ceiling that inspects only the target" lesson, #1545/MACH-001. Guard:
  `rbac_grant_ceiling_test.go` (`TestAssignUserRole_RequiresActorHoldRolePermissions`,
  `TestAssignUserRole_ScopedHolderCannotGrantAtBroaderScope`),
  `authz_guard_functions_test.go` (`TestRequireMachinePrivilegeCeiling_*`).
- **INV-CORE-02** A machine identity can never be granted a role at global scope. Why:
  ADR-091. Guard: `TestAssignMachineRole_GlobalScopeRejected` (adr-conformance, default-ci).
- **INV-CORE-03** A machine granter acting directly (`WithSelfMachineGranter`) must hold every
  permission the target role bundles before it can grant that role; an untagged/ambient context
  fails closed. Why: #1542. Guard: `authz_machine_granter_ceiling_test.go`,
  `groups_add_member_machine_ceiling_test.go:TestAddUserToGroup_MachineGranterUntaggedContextFailsClosed`.
- **INV-CORE-04** An admin-rank-ceiling resolution failure (a storage error resolving the
  target's authority) fails CLOSED and must not masquerade as an ordinary 403. Why: incident
  after RemoteStorage deletion (#2162), found by `FuzzStorageFaultOperations`
  (REPLAY_HEX=1829d438). Guard:
  `admin_rank_ceiling_fail_closed_test.go:TestAdminRankCeiling_ResolutionFailureFailsClosed`.
- **INV-CORE-05** `IsGlobalAdmin`'s PAT-restriction short-circuit must never be asked about a
  THIRD PARTY; `guardLastAdminDeactivation`/`SuspendInactiveUsers` ask about the TARGET's admin
  status, never the acting caller's own PAT restriction. Why: security-closures
  `LASTADMIN-PAT-CONFUSED-DEPUTY`, ADR-conformance `ADR-042-LASTADMIN-NOT-PAT-CONFUSED` /
  `ADR-042-INACTIVITY-SWEEP-NOT-PAT-CONFUSED`. Guard:
  `TestGuardLastAdminDeactivation_NotFooledByActingCallersPATRestriction`,
  `TestSuspendInactiveUsers_NotFooledByCallersPATRestriction`.
- **INV-CORE-06** Every `actorID == 0` comparison in non-test source is classified
  (audit-only vs. per-actor ceiling) in an exhaustive allowlist; an unclassified comparison, or
  an open gap not explicitly tracked, fails the build. Why: #1524/#1532. Guard:
  `actor_sentinel_completeness_test.go` (`TestActorSentinelComparisonsAreAllowlisted`,
  `TestActorSentinelOpenGapsAreTracked`).
- **INV-CORE-07** `transferOwnership` is the ONE authorization-checked path allowed to assign
  `SecretNode.OwnerID`; no other function writes that field directly. Why: G10/#1413. Guard:
  `secret_ownership_guard_test.go` (AST sweep + allowlist).
- **INV-CORE-08** Every `HasActiveMFAStepUp`/`GetActiveMFAStepUpGrant`/`ConsumeMFAStepUpGrant`
  call site pins a hardcoded `models.MFAStepUpPurpose*` constant matching its own allowlisted
  expectation — a variable/field purpose argument is a confused-deputy risk. Why: fixed
  confused-deputy MFA step-up bypass. Guard:
  `mfa_stepup_purpose_guard_test.go:TestMFAStepUpConsumersUseExpectedPurpose`.
- **INV-CORE-09** `cachedImpersonationCeiling`'s TTL check uses bare `c.now()`, never an
  `effectiveNow`/`.UTC()` wrapper — the latter would re-widen the trust window on a backward
  wall-clock step. Why: #1983/#1994/#1995 investigation. Guard:
  `impersonation_ceiling_monotonic_test.go`.
- **INV-CORE-10** `requireEqualOrGreaterAdminAuthority` compares actual bundled PERMISSIONS,
  never role-NAME membership, and correctly resolves a `BypassesPermissionChecks` role with
  empty explicit `RolePermission` rows (empty permissions is not "nothing to check"). Why:
  #G05, S1 sweep (#2012). Guard: `authz_guard_functions_test.go:TestRequireAdminAuthorityAt_*`.
- **INV-CORE-11** `AssignMachineRole`/`AssignRoleToGroup`/`AssignGroupRoleWithExpiry`/
  `AddUserToGroup`/`AddProjectMember`/`SetProjectMemberRole`/`CreateUserWithAssignments` all
  refuse escalation-by-proxy (granting a role the actor doesn't itself hold the permissions
  for). Why: #93/#107/#141/#231/#480. Guard: `authz_admin_ceiling_group_test.go`,
  `users_atomic_ceiling_test.go` (`TestCreateUserWithAssignments_Rejects*`).
- **INV-CORE-12** `RestoreGroup`/`RestoreProject`/`RestoreEnvironment` re-apply the admin-rank
  ceiling when the restored entity holds an admin role. Guard: `restore_admin_ceiling_test.go`.
- **INV-CORE-13** An `/system` proxy relay granter refuses admin-tier role grants — no
  delegation of admin-tier grants through the relay path. Why: ADR-087/088/093. Guard:
  `authz_system_proxy_relay_ceiling_test.go:TestSystemProxyRelayGranter_RefusesAdminTierRoles`.
- **INV-CORE-14** `requireGranterHoldsRolePermissions`'s other callers (`AddProjectMember`'s
  own callers, the `AssignRole` endpoint, access-request approval) pass `actorIsMachine=false`
  unconditionally — a sibling gap to the fixed `AssignRoleWithExpiryProxy` path, left open per
  the allowlist note. Why: `actor_sentinel_completeness_test.go` note. UNGUARDED (#issue: audit
  whether these call sites can be reached by a genuine machine actor and close if so).

## Last-admin / lockout

- **INV-CORE-15** An install is never left with zero global administrators across
  `SuspendUser`, self-deactivation, `RemoveRoleFromGroup`, `DeleteGroup`,
  `RemoveUserFromGroup`, SCIM user-update/group-deprovision, and project-scoped group-admin
  removal — checked at the PRIMITIVE, not only at entry points. Why: #93/#107/#G02,
  security-closures `FIX-2-primitive`/`FIX-2-sso`. Guard: `last_admin_guard_wiring_test.go`,
  `last_admin_guard_external_test.go`, `group_admin_guard_test.go`,
  `project_scoped_group_admin_guard_test.go`, `scim_guards_test.go`.
  Every path counts **live holders, not grant rows** (#2658): a user grant counts only for
  a non-deleted, `IsActive`, non-login-blocked user (not suspended/deprovisioned); a group
  grant only for a non-deleted group with at least one such global member. Core's
  `filterActiveHolders` and storage's `RemoveGlobalAdminRoleGuarded`
  (`globalAdminAssignmentHasLiveHolder`) apply the same rule, and `RemoveUserRole`'s global
  admin branch holds `lastAdminGuardLockKey` like every other last-admin writer. Guard:
  `TestCTAReview_RemoveUserRole_LastGlobalAdmin_AfterAdminGroupDeleted` (+ `_Postgres`),
  `TestCTAReview_RemoveUserRole_LiveAdminStillCounts`,
  `TestGlobalAdminLiveAccountStates_MatchAccountLoginBlocked`.
- **INV-CORE-16** The last-admin check fails closed when `IsGlobalAdmin` itself errors, never
  silently allows. Guard: `scim_guards_test.go:TestGuardLastAdminDeactivation_FailsClosedOnIsGlobalAdminError`.
- **INV-CORE-17** A direct-grant race and a group-role-grant race against the last-admin / SoD
  invariant serialize across independent Postgres connections (replicas), not just in-process.
  Why: security-closures `G04-HA-1646`, `G04-HA-1780`. Guard:
  `TestConcurrency_AssignUserRole_CrossReplicaPostgres_SoDBypass`,
  `TestConcurrency_GroupRoleGrant_CrossReplicaPostgres_SoDBypass` (pg-gated).

## Admin bypass / RBAC structural marker (ADR-084, ADR-044)

- **INV-CORE-18** `bypasses_permission_checks` is a structural, non-name-based column on
  `models.Role` resolved via `storage.RoleSetBypassesPermissionChecks` — never a hardcoded
  role-name list. Why: ADR-084. Guard:
  `adr_open_decisions_tripwire_test.go:TestADRDecisionRoleSetContainsAdminIsStructural`.
- **INV-CORE-19** `roleSetContainsAdmin` fails closed on a genuine storage error, never
  swallows it. Why: ADR-084 "Verification". Guard: `role_set_contains_admin_error_test.go`.
- **INV-CORE-20** `installAdminRoleIDSet` (`rbac_management.go`) is STILL a second,
  separately-maintained name-based admin-role list — ADR-084's own documented "not yet done".
  Why: ADR-084. UNGUARDED (#issue: fold into the structural `bypasses_permission_checks`
  resolution or justify why a second list must remain).
- **INV-CORE-21** On every startup, newly-added canonical permissions reconcile additively
  into existing installs' baseline roles — non-clobbering of existing grants, no-op on a
  pre-bootstrap install, idempotent, and the grant itself audited. Why: ADR-044. Guard:
  `rbac_reconcile_test.go` (`TestReconcileRBAC_*`), `alerts_write_role_reconcile_test.go`,
  `user_baseline_role_reconcile_test.go`.

## Audit (ADR-029)

- **INV-CORE-22** Every audit-emitting path funnels through the single choke point
  `emitAudit`, which stamps `MachineIdentityID` from context and clears `UserID` for
  machine-actor-typed events; a direct `storage.LogAuditEvent` bypassing it must be in a
  reviewed, reasoned allowlist. Why: #1530, #1626/#1628. Guard:
  `g80_1530_machine_actor_attribution_guard_test.go` (repo-wide AST/substring sweep +
  allowlist).
- **INV-CORE-23** Admin-only config mutations (notification-channel CRUD, anomaly-config
  update) call the shared `writeConfigChangeAuditEvent` helper. Guard:
  `config_change_audit_guard_test.go:TestGuardedConfigMutations_CallSharedAuditHelper`
  (red/green-verified by removing the call).
- **INV-CORE-24** Audit-log retention purge does not break the hash chain's verifiability,
  re-anchors/checkpoints correctly, and a forged retention anchor is rejected; an attacker
  deleting an anchored row is still detected. Why: ADR-029 retention extension. Guard:
  `audit_retention_reanchor_test.go` (`TestPurgeAuditLogs_ChainVerifiesAfterPurge`,
  `TestWriteAuditCheckpoint_SucceedsAfterPurge`,
  `TestPurgeAuditLogs_AttackerDeletesAnchoredRow_StillDetected`,
  `TestVerifyAuditChain_ForgedRetentionAnchorRejected`).
- **INV-CORE-25** Audit-log retention purge is blocked by an active legal hold; retention-days
  below the configured minimum is rejected. Guard: `audit_log_retention_test.go`
  (`TestPurgeAuditLogs_LegalHoldBlocked`, `TestPurgeAuditLogs_RetentionDaysBelowMin`).
- **INV-CORE-26** Break-glass revocation atomically removes the role AND updates activation
  state in one transaction, with audit emission strictly after commit. Why: security-closures
  `breakglass-revoke-half-commit-001`. Guard: `FuzzStorageFaultOperations` permanent corpus
  entry `7c0a2492ee5d1dfa`; fix is `core.RevokeBreakGlassActivationAtomic`.

## Soft-delete / purge (ADR-032, ADR-033)

- **INV-CORE-27** The purge scheduler re-checks the legal hold itself at purge time, not only
  at the scheduler's pre-lock check (closes a TOCTOU); an unknown hold status aborts (fails
  safe), never proceeds. Why: ADR-032. Guard:
  `purge_test.go:TestPurgeExpiredSoftDeletes_AbortsUnderActiveLegalHold`,
  `_AbortsWhenHoldStatusUnknown`.
- **INV-CORE-28** `PurgeExpiredSoftDeletes` emits exactly one system-actored `data.purged`
  audit event with counts when anything was purged, and none when nothing was. Guard:
  `purge_test.go:TestPurgeExpiredSoftDeletes_CountsAndAudits`, `_NoAuditWhenNothingPurged`.
- **INV-CORE-29** Each soft-deleted entity (users/projects/environments/secrets) is purged
  independently on its own `deleted_at`; no cascade logic lives in the purge job itself. Why:
  ADR-032 "Decision". UNGUARDED (#issue: the four `Purge*Before` mock expectations in
  `purge_test.go` imply but don't directly assert non-cascading independence — add a direct
  test or a structural check).
- **INV-CORE-30** `SecretNode.DeletedAt` soft-delete is respected by every raw/Table/Joins
  query touching `secret_nodes` — GORM auto-scopes model-based queries but not raw SQL. Why:
  ADR-033 (names six specific call sites). UNGUARDED (#issue: no repo-wide completeness sweep
  exists over raw queries against `secret_nodes`, unlike the CSV-writer or account-state
  exhaustiveness guards — only point tests like `catalog_delete_project_test.go` cover it).

## Secret dependency graph (ADR-052)

- **INV-CORE-31** The dependency graph stays an acyclic DAG confined to one project AND one
  environment; an edge that would cycle, cross a project/environment boundary, duplicate,
  self-reference, or reference a non-existent secret is rejected, including under concurrent
  adds. Why: ADR-052. Guard: `secret_dependencies_test.go`
  (`TestTopologicalRotationOrderDetectsCycle`, `TestAddSecretDependency_Validation`,
  `TestAddSecretDependency_CrossEnvironmentRejected`,
  `TestAddSecretDependency_ConcurrentRaceCannotPersistACycle`). Cross-replica (#2660): that
  concurrency guard races goroutines through ONE `KeyorixCore` on SQLite, and
  `CreateSecretDependencyExclusive`'s `FOR UPDATE` on existing edges does not stop a second
  replica's add (READ COMMITTED snapshot excludes the first's new edge), so every edge insert
  runs under `WithNamedLock(secretDependencyGraphLockKey(project))` in
  `LockedCreateSecretDependencyExclusive`, the only path `AddSecretDependency` uses. Guard:
  `TestCTAReview_AddSecretDependency_CrossReplicaCycle_Postgres` (pg-gated).
  `TestCTAReview_AddSecretDependency_CrossReplicaCycle_Postgres` reproduces it (skipped until
  #2660 is fixed).
- **INV-CORE-32** Dependency reads (impact/order) are filtered by environment, and `DELETE`
  requires the edge to reference the path secret (closes a cross-environment IDOR). Guard:
  `TestSecretDependencyReadsFilterByEnvironment`, `TestRemoveSecretDependency_RequiresFocalReference`.
- **INV-CORE-33** A best-effort dependency-lifecycle emission (`emitDependencyLifecycleEvents`)
  recovers from a panic — never lets it propagate past an already-committed delete/restore.
  Why: security-closures `secret-delete-restore-dependency-emission-panic-001`. Guard:
  `FuzzStorageFaultOperations` corpus entry `059212c4cda84764`; `recover()` at
  `secret_dependencies.go:366`.

## Post-commit best-effort panics never mask a committed write

- **INV-CORE-34** A panic in a best-effort, post-commit step is recovered and logged, never
  allowed to propagate and misreport an already-committed write as a failure. Recurring
  defect class, 6+ confirmed live instances (`CreateUser`'s password-history/system_viewer
  auto-assign, `CreateProject`/`CreateProjectWithEnvs`'s environment seeding, break-glass
  revoke's cache eviction, `TransitionMachineIdentity`'s auth-cache eviction, `mintSession`'s
  `EnforceSessionLimit` call, `emitAudit`'s own `LogAuditEvent` call). Why: security-closures
  `createuser-best-effort-panic-002`, `createproject-environment-seed-panic-003`,
  `breakglass-revoke-cache-evict-panic-001`, `machine-identity-evict-panic-fail-closed-001`.
  Guard: `mint_session_enforce_limit_panic_test.go:TestLogin_EnforceSessionLimitPanic_StillSucceeds`;
  `recover()` confirmed at `account.go:161,196`, `audit_context.go:197`, `auth.go:200`,
  `auth_bootstrap.go:469`, `break_glass.go:439`, `catalog.go:278,641`,
  `classification_gate.go:484`, `machine_identities.go:272`, `secret_dependencies.go:366`,
  `service.go:662`, `users.go:222,264`. **No structural completeness guard enumerates every
  best-effort post-commit call site** — each was a point-fix after a live finding. UNGUARDED
  as a class (#issue: an AST sweep analogous to `atomicity_guard_test.go` that requires every
  deferred/best-effort post-commit call to be wrapped in `recover()` or be on a reviewed
  allowlist).

## Atomicity / transactions

- **INV-CORE-42** `provisionInvitationSetupLink` (`InviteToProjectWithLink`/`InviteGlobalWithLink`)
  persists the invitation without a link ONLY on a benign condition (base_url unset, a real
  throttle verdict). A storage fault — the mint step (#2444) or the resend throttle's own count
  query (`ErrResendThrottleUnverifiable`, #2599) — persists nothing and returns a nil invitation;
  the throttle itself stays fail-closed either way. Why: #2599, found by
  `FuzzStorageFaultOperations`. Guard:
  `invitation_throttle_count_error_test.go` (`TestInviteGlobalWithLink_ThrottleCountErrorPersistsNothing`,
  `TestInviteGlobalWithLink_ThrottleLimitReachedStillPersistsInvitation`), corpus seeds `2599_*`.
- **INV-CORE-35** Every non-test `*KeyorixCore`/`*AnomalyDetector` function making 2+
  storage/core writes outside `WithTransaction` is a reviewed, classified entry in
  `docs/atomicity-exempt.tsv` (A fix-required / B consume-first / C independent-by-design /
  D false-positive / S saga); an unclassified hit fails CI. Why: Session O (G80 campaign).
  Guard: `atomicity_guard_test.go:TestAtomicityGuard_UnclassifiedMultiWriteFunction` (AST walk
  — no control-flow awareness; documented blind spot for mutually-exclusive branches).
- **INV-CORE-36** A storage call never escapes its own `WithTransaction` closure (never rolled
  back with the rest; SQLite single-connection deadlock risk) — never exemptable, always a bug.
  Guard: `atomicity_guard_test.go:TestAtomicityGuard_TransactionEscape`.
- **INV-CORE-37** A SUCCESS audit event never textually precedes the storage write it reports
  on, in the same function; denial/failure events are exempt by construction, anything else
  needs a reviewed `AUDIT:<fn>` exemption. Guard: `atomicity_guard_test.go:TestAtomicityGuard_AuditBeforeWrite`.
- **INV-CORE-41** `DecideAccessReviewItem`'s attest path does every fallible read
  (reviewer controls, the live grant re-verification) BEFORE the conditional claim that commits
  the item's decision, and nothing that can fail after it — so a reported error means the item
  is still pending. (The revoke path must act after its claim to keep the #1646 race closed; its
  post-claim failure window is logged as `SECURITY: ... manual reconciliation required`.) Why:
  #2570, found by `FuzzStorageFaultOperations`. Guard:
  `access_review_decide_read_before_write_test.go:TestDecideAccessReviewItem_AttestGrantLookupErrorLeavesItemPending`,
  corpus seed `2570_decideaccessreviewitem_listprojectroleassignments_error`.

## Check-then-act across replicas (GUARD-2)

- **INV-CORE-41** Every function where a `require*`/`guard*` security check precedes a later
  storage/core write with no shared `storage.WithNamedLock` is a reviewed entry in
  `docs/check-then-act-lock-exempt.tsv`; rows the independent second review (#2564) found to
  be real cross-replica races are kept as `UNSAFE-OPEN` with a tracking issue and a skipped
  two-replica Postgres repro in `concurrency_check_then_act_exempt_review_postgres_test.go`.
  Guard: `check_then_act_lock_guard_test.go:TestCheckThenActLockGuard_UnlockedSecurityCheck`
  (AST walk; no control-flow, interprocedural, or `tx.<Write>` awareness — and it does not
  detect stale rows, see the TSV's `STALE` class). Open: #2646 #2647 #2649 #2650 #2651
  #2652 #2653 #2654 #2655 #2656 #2657 #2659.
  detect stale rows, see the TSV's `STALE` class). Open: #2646 #2647 #2648 #2649 #2650 #2651
  #2652 #2653 #2654 #2656 #2657 #2659.
  #2652 #2653 #2654 #2655 #2656.
  #2652 #2655 #2656 #2657 #2659.
  detect stale rows, see the TSV's `STALE` class). Open: #2648 #2649 #2650 #2651
  detect stale rows, see the TSV's `STALE` class). Open: #2648 #2649 #2650 #2651
  detect stale rows, see the TSV's `STALE` class). Open: #2648 #2650 #2651
  #2652 #2653 #2654 #2655 #2656 #2657 #2659. Closed rows move to class `PARENT-LOCKED`
  detect stale rows, see the TSV's `STALE` class). Open: #2648 #2649 #2650 #2651
  detect stale rows, see the TSV's `STALE` class). Open: #2648 #2650 #2651
  #2653 #2654 #2655 #2656 #2657 #2659. Closed rows move to class `PARENT-LOCKED`
  (INV-STORE-21) or are removed when a `WithNamedLock` now covers them.
- **INV-CORE-42** A write that persists a pre-read snapshot must not overwrite columns the
  operation did not change, and must not resurrect a soft-deleted row. GORM `Save(struct)` on
  a soft-delete model is a resurrection primitive under concurrency: its `UPDATE ... WHERE
  deleted_at IS NULL` matches 0 rows and it falls back to `INSERT ... ON CONFLICT (id) DO
  UPDATE SET <all columns>` including `deleted_at = NULL`; `Select("*").Updates(...)` reverts
  every column a narrower concurrent writer (`SetAccountState`, `SetPasswordHash`, …) changed.
  Why: C-GUARD2-EXEMPT-REVIEW. Guard: share permission update (#2648, fixed):
  `share_permission_column_scoped_guard_test.go:TestUpdateSharePermission_IsColumnScoped` +
  `TestCTAReview_UpdateSharePermission_vs_RevokeShare_CrossReplicaPostgres` (pg-gated).
  UNGUARDED: #2650 secret undelete, #2651 dynamic config re-enable, #2653/#2654 user
  suspension/password revert.
  Why: C-GUARD2-EXEMPT-REVIEW. Guard: UNGUARDED (#2648 share revoke, #2650 secret undelete,
  #2651 dynamic config re-enable, #2653/#2654 user suspension/password revert).
- **INV-CORE-43** `ActivateMFA` only ever activates the TOTP secret the submitted code was
  validated against: `ActivateMFASecret` is a conditional write pinned to that row's
  ciphertext, and a mismatch (a concurrent `BeginMFAEnrollment` swapped the secret) fails the
  whole activation closed with `ErrMFAEnrollmentChanged`. Why: #2655. Guard:
  `TestActivateMFA_SecretSwappedAfterValidation_FailsClosed` (default-ci),
  `TestCTAReview_ActivateMFA_vs_BeginMFAEnrollment_CrossReplicaPostgres` (pg-gated).
- **INV-CORE-44** A project membership never ends `revoked` while its user still holds the
  role grant that membership conferred: every write moving a (project, user) membership into
  or out of `active` (`TransitionMembership`, `inviteMemberWithMode`) runs its state change
  and its grant/removal side effect under `WithNamedLock(membershipLockKey(project, user))`.
  Why: #2657, #2659. Guard:
  `TestCTAReview_TransitionMembership_ActivateVsRevoke_CrossReplicaPostgres`,
  `TestCTAReview_InviteMemberOpenMode_vs_Revoke_CrossReplicaPostgres` (pg-gated).
  Why: C-GUARD2-EXEMPT-REVIEW. Guard: user profile writes (#2653/#2654, fixed):
  `user_profile_column_scoped_guard_test.go:TestUserProfileWrites_AreColumnScoped` +
  `TestCTAReview_UpdateUser_vs_SuspendUser_CrossReplicaPostgres` /
  `TestCTAReview_UpdateOwnProfile_vs_ChangePassword_CrossReplicaPostgres` (pg-gated).
  An operation whose NEW `account_state` is derived from the one it read (the SCIM lifecycle
  paths: `scimUpdateUserTx`, `DeprovisionSCIMUser`) writes it only through
  `SetAccountStateIfMatches` conditioned on that read value, never the blind
  `SetAccountState`, and fails closed with `ErrUserAccountStateConflict` on a miss
  (C-RACE-FIX-B2): `scim_account_state_conditional_guard_test.go:TestSCIMAccountStateWrites_AreConditional`,
  `scim_account_state_persisted_test.go`, and
  `TestCTAReview_SCIM_vs_SuspendUser_WithoutRowLock_CrossReplicaPostgres` (pg-gated).
  UNGUARDED: #2648 share revoke, #2650 secret undelete, #2651 dynamic config re-enable.

## Account-state / exhaustiveness

- **INV-CORE-38** Every `AccountXxx` constant declared in `account_state.go` is explicitly
  listed in `AccountLoginBlocked`'s switch — never a silent default fall-through. Why: ADR-025.
  Guard: `account_state_exhaustiveness_guard_test.go:TestAccountLoginBlocked_ExhaustsStateRegistry`
  (self-test: `TestAccountStateExhaustivenessScannerDetectsAMissingCase`).
- **INV-CORE-39** Every function constructing an `encoding/csv.Writer` anywhere in the repo
  calls a CSV-safety encoder (`csvSafe`/`CSVSafe`) — CSV formula injection (CWE-1236) recurred
  5+ times historically across campaigns. Why: security-closures `FIX-8-csv`. Guard:
  `csv_writer_completeness_test.go`, `TestCSVWriters_EncodeAgainstFormulaInjection`.
- **INV-CORE-40** `internal/core` production code depends on zero cloud SDK / integration
  packages (dependency inversion to `internal/core/ports`). Why: ADR-109. Guard:
  `dependency_guard_test.go:TestCoreIntegrationDepsAllowlistIsEmpty`,
  `TestCoreIntegrationDepsMatchADR109Allowlist`.

## Cross-replica check-then-act serialization (GUARD-2)

- **INV-CORE-41** Every security-relevant check-then-act decision in `internal/core` (an
  authorizer/role/SoD/admin-count/quorum read that decides whether a write proceeds) that is
  check-then-act at all serializes its check AND the write it gates under the SAME
  `storage.WithNamedLock` acquisition (or an equivalent DB-level primitive — a row lock inside
  `WithTransaction`, or a conditional `UPDATE ... WHERE` that fails closed on a stale read) —
  never an in-process mutex alone, which only serializes callers within ONE process and is
  silently absent the moment two replicas of an HA deployment (ADR-039) each take the request.
  Extends INV-CORE-17's two originally-fixed cases (`AssignUserRole`/`AssignRoleToGroup`) with
  two more found by this inventory sweep: `AssignMachineRole`'s SoD check (previously
  serialized by NOTHING at all, not even an in-process mutex) and `UpdateSCIMUser`/
  `DeprovisionSCIMUser`'s last-admin guard (previously `accountStateMu` only, cross-replica-
  unsafe — a gap the code's own prior comment had already named and deliberately deferred).
  Why: QA-1 report pattern #3 (~51 PRs of this shape), #1646, #1780, #1955.
  Full inventory: `docs/specs/check-then-act-inventory.md`. Guard (regression, the two new
  cases): `TestConcurrency_AssignMachineRole_CrossReplicaPostgres_SoDBypass`,
  `TestConcurrency_UpdateSCIMUser_CrossReplicaPostgres_LastAdminGuard` (pg-gated). Guard
  (structural, enforces this rule going forward for NEW code):
  `check_then_act_lock_guard_test.go:TestCheckThenActLockGuard_UnlockedSecurityCheck` (AST
  walk over every `require*`/`guard*` check call followed by a later write with no shared
  `storage.WithNamedLock` — no control-flow awareness, same documented blind spot as
  INV-CORE-35's atomicity guard; unclassified hits fail CI, reviewed false positives live in
  `docs/check-then-act-lock-exempt.tsv`). CI: `.github/workflows/pg-race-tests.yml` runs every
  pg-gated test in this family against real Postgres on any PR touching `internal/core` or
  `internal/storage`, plus nightly on `main` — closing the gap where `ci.yml`'s own
  Postgres-backed "core" leg only runs on `push`/`merge_group`/`ci:full`-labeled PRs, not an
  ordinary PR.
## Anomaly detection

- **INV-CORE-41** The incremental anomaly sweep records exactly the alerts a full sweep over
  every secret would: its candidate horizon is never narrower than the widest per-secret rule
  look-back (`cumulativeRateHorizon`, 24h), and a failed candidate query falls back to the full
  sweep rather than skipping secrets. Why: PERF-2 performance study (C-PERF-FIXES); the obvious
  "only secrets touched since the last run" filter silently drops `cumulative_rate`. Guard:
  `anomaly_incremental_test.go` (`TestRunDetection_IncrementalSweepDetectsSameAnomaliesAsFullSweep`
  — every rule type, real SQLite storage; `TestRunDetection_CandidateQueryFailureFallsBackToFullSweep`).
- **INV-CORE-42** No access log falls between two anomaly passes unexamined: a pass's scan
  window extends back to the persisted high-water mark of the last fully-successful pass
  (capped at `maxDetectionCatchUp`), and a pass with storage failures does not advance it. This
  is what makes the deferred, jittered first pass after startup safe. Guard:
  `anomaly_incremental_test.go:TestRunDetection_HighWaterMarkClosesTheGapBetweenPasses`;
  scheduler side `server/anomaly_scheduler_start_test.go:TestAnomalyScheduler_FirstPassIsDeferred`.

## Fuzzer oracles exercising internal/core directly

- Oracle (a) atomicity, (c) fail-closed authz on a storage-read fault, (d) effect-then-error
  never a mix, (e) no secret plaintext in an error body — all four checked by
  `FuzzStorageFaultOperations` (`server/faultops/fuzz_storage_fault_operations_test.go`)
  driving real `internal/core` calls through REST/system/gRPC transports.
- `FuzzAuthCacheDifferential` (`server/middleware`) — cached vs. cache-bypassed auth decisions
  must agree for every account-state transition; found `account-state-reactivate-pat-tombstone-001`
  live in `internal/core/account_state.go`.
- `FuzzConcurrentOpsLinearizable` (`server/http`) — calls `core.KeyorixCore` directly; a
  revocation must be visible to every later read.

See `server/faultops/INVARIANTS.md` (or `server/http/INVARIANTS.md`) for the oracle definitions
themselves; they are recorded here only insofar as they exercise this package.
