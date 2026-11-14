# Open-issue audit, 2026-11-14 (ISSUE-AUDIT-NOV-1)

Why: PLANNER-11140103 checked 12 old items against `origin/main` and 9 were already fixed with the
issue still open. This file settles the list below once, so a reader can tell which issues are real.

Base: `origin/main` at `77a7c2576b95` (fresh `kclone`, `ktree origin/main` clean). Read-only audit:
no production code is changed by this PR.

Verdicts:

- **FIXED**: the code on `origin/main` does what the issue asks. Evidence is a file:line or a test name.
- **OPEN**: the defect or gap is still on `origin/main`, with a one-line repro and, where it applies, the owner.
- **OBSOLETE**: the premise is gone and nothing is left to do. No issue in this audit landed here.
- **NEEDS DECISION**: the code cannot settle it. The question is stated for the coordinator or Andrei.

Tests quoted as "pass" were run on this tree with `~/.claude/scripts/gotest.sh` (tree `77a7c2576b95`, clean).
Postgres tests ran against a `kpg` database. No issue was fixed in this PR (see "Fixes in this PR").

## Group 1: core and storage leftovers

| Issue | Verdict | Evidence | Note |
|---|---|---|---|
| #3428 UnlockUser clears the lockout before a best-effort audit write | FIXED | `internal/core/login_lockout.go:497-514` (UNLOCK-AUDIT-1): the clear and the `account.unlocked` row commit in one `withAuditedMutation` transaction; an audit error or panic rolls the clear back. `TestUnlockUser_AuditWriteError_LeavesLockoutSet`, `TestUnlockUser_AuditWritePanic_LeavesLockoutSet` (`internal/core/unlock_user_audit_fail_closed_test.go:40,62`) pass. | Option (a) of the issue (audit first, fail closed). |
| #3420 Break-glass activation audit after commit | FIXED | `internal/core/break_glass.go` `ActivateBreakGlass` / `activateBreakGlassDegraded` (BREAKGLASS-OWED-1): a refused audit write commits a degraded, short-expiry activation with an owed-audit record; if the owed record cannot commit either, the activation is refused. `TestBreakGlass_AuditRefusedCommitsDegradedWithOwedRecord` (`internal/core/break_glass_degraded_test.go:302`) passes. `docs/security/threat-models/break-glass.md` BG-6 now cites these tests instead of a GAP. | |
| #3350 RevokeShare: CreateNotification panic after the committed revoke answers 500 | FIXED | `internal/core/sharing.go:394-398` calls `notifySecretShareRevoked` / `notifyGroupSecretShareRevoked`, which run under `runPostCommitNotificationFor` (`internal/core/notifications.go:445-480`). `TestRevokeShare_CreateNotificationPanic_ReportsSuccess_3350` (`server/faultops/oracle_a_revoke_share_notify_panic_3350_test.go:16`), `TestShareNotifiers_PanicAfterCommit_StillSucceeds`, `TestShareNotifiers_FailedNotificationAfterCommit_IsRecorded`, `TestShareNotifiers_PanickingGroupMemberLookup_DoesNotFailTheRevoke` pass. | The `knownOpenTolerances` entry the issue mentions is gone (`rg 3350 server/faultops` finds only the regression tests). |
| #2887 DeleteProjectIfEmpty counts before taking the project lock | FIXED | `internal/storage/store/local_secrets.go:393-409`: `lockProjectRowForCascade(tx, id)` runs before the `Count`. `TestConcurrency_DeleteProjectIfEmpty_LockFirstPreventsOrphanedDelete` (`internal/storage/store/concurrency_delete_project_if_empty_postgres_test.go:40`) passes on Postgres (ran, not skipped). | |
| #2812 migrate-from-user SetAccountState error | FIXED | The issue's option 2 was taken (#2867): `internal/core/migrate_user_to_machine.go:70-149` creates the identity and suspends the source user in ONE `WithTransaction`, every refusal before either write. `TestMigrateUserToMachine_FaultedSuspendRollsBackTheIdentity` (`internal/core/migrate_user_to_machine_partial_test.go:196`) passes. No `SetAccountState` tolerance for this op remains in `server/faultops`. | The "partial state reported in the error" premise no longer exists. |
| #3362 Suspend clear marker and an old-binary resume | FIXED | `internal/storage/store/secret_suspend_marker_trigger.go`: a PostgreSQL BEFORE UPDATE trigger clears `suspend_clear_synced_copies` whenever `status` moves to anything but `suspended`, so an old binary's resume clears it too. Schema floor `minCompatibleSchemaEpoch = 3` (`internal/storage/factory_schema_epoch.go:127`) stops old binaries from starting once migrated. `TestSecretSuspendMarker_ClearedByOldBinaryResume_Postgres` (`internal/storage/factory_rolling_upgrade_triggers_postgres_test.go:18`) passes on Postgres (ran, not skipped). | Both fix directions of the issue are in. |
| #2842 Oracle (a) flags RotateSecret's non-transactional version write (rollback, UpdateSecret error) | FIXED | `internal/core/secrets.go:784-818` (AUDIT-MUTATION-TX-1): `oneTx = secret.RotationBackend == "" \|\| rollback`, so a rollback commits version, timestamp and audit row in one transaction. `server/faultops/oracle_a_by_design_test.go:642` records that this removed the last `#2842` tolerance. `TestSecretMutationAuditFailure_FailsClosedChangesNothing` (`server/faultops/secret_mutation_audit_fail_closed_test.go:46`, covers `REST POST /api/v1/secrets/{id}/rollback`) passes. | Residual, not a defect: a backend-bound rotate stays two writes by design (`secrets.go:771-782`, version must survive an applied upstream change). The issue's item 1 (a write-count ledger row for it) was not done: `docs/atomicity-exempt.tsv` has only the `AUDIT:` row for `rotateSecret` (line 96). Nothing fails today, so this is a documentation gap for the ledger owner. |
| #2839 SAML ACS JIT user left on a mintSession failure; 4 success-branch diffs; oracle (c) on PUT /auth/profile | FIXED | All three parts have an answer. (1) Class C decision: ledger row `JIT:(*KeyorixCore).CompleteSAML`, enforced by `server/faultops/zz_sso_class_c_oracle_test.go` (`TestSSOClassCRule_MatchesAtomicityLedger`, `_Calibration`, `_IsLoadBearing`). (2) Success-branch diffs: the SAML fixture subject is deterministic (`zz_saml_acs_op_test.go:193-233`, #2910) and the seed `UpdateLastLogin#1` runs (`fuzz_storage_fault_operations_test.go:524`). (3) `non_load_bearing_authz_read_entry_put_auth_profile_getuserpermissions_1_test.go` traces the route and `TestNonLoadBearingAuthzRead_ProfileUpdateGetUserPermissions` passes. | |

