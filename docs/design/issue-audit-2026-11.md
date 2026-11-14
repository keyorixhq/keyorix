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

## Group 2: test and tooling leftovers

| Issue | Verdict | Evidence | Note |
|---|---|---|---|
| #3445 OpenAPI lint: decide on vacuum's extra rules | NEEDS DECISION | `.vacuum.yaml:101-107` still has `camel-case-properties`, `oas3-missing-example`, `oas3-parameter-description`, `description-duplication`, `component-description`, `oas-missing-type` set to `false` with only the finding counts as comments. No per-rule decision is recorded. | Question for Andrei: per rule, enable (and fix in batches) or record why it stays off (camel-case is likely won't-fix, the API is snake_case). Enabling goes through the `.github` lint step, which this session may not touch. |
| #3444 GET /secrets/{id}/versions and gRPC GetSecretVersions always count total_reads | NEEDS DECISION | Unchanged: `server/http/handlers/secrets_versions.go:84` calls `SecretTotalReads` on every request, and `server/grpc/services/secret_service.go:491` sets `TotalReads` unconditionally (`GetSecret` is opt-in via `GetIncludeTotalReads`, line 135). | Repro: `GET /api/v1/secrets/{id}/versions` runs the access-log count on every call. Question: make it opt-in like #3113 (`include_total_reads`, with web, CLI and SDK callers updated in the same PR) or keep it and say why. An API-shape change across callers, not fixed here. |
| #3454 Credential-read fold follow-ups | FIXED | (1) `FuzzAuthCacheDifferential` has the folded arm: `case 12` and `acCheckFoldedDifferential` (`server/middleware/authcache_differential_fuzz_test.go:398,459`), `TestAuthCacheDifferential_FoldedArmEngagesTheFold` (line 615). (2) Relabel and classification cases in the fold tests: `TestFoldedCredential_CredentialRelabelIsNotADecision`, `TestFoldedCredential_CrossReplicaInvalidation` (`server/http/folded_credential_test.go:331,250`), per `changelog.d/backlog-lane-1-lever2-followups.md`. (3) `server/middleware/credential_read_fold.go:12-20` documents that the fold needs the secret in this replica's node cache. `FuzzAuthCacheDifferential` seeds and `TestFoldedCredential_CredentialRelabelIsNotADecision` pass. | Files are in OPT-READPATH-2's area; read only. I did not locate a test whose name says "classification" for item 2; the claim rests on the changelog fragment and the cross-replica test. |
| #3463 SCIM routes have no real-server e2e coverage | FIXED | The harness mints a SCIM token: `scripts/e2e/harness/harness.go:166-225,345-348` (`DBBackend.EnableSCIM`, `Server.SCIMToken`). `scripts/e2e/api_smoke_test.go:168` runs `groupSCIM`; `TestJourney_SCIMProvisioning` (`scripts/e2e/journeys/journey_scim_provisioning_test.go:65`). `scripts/e2e/routes.json:4403-4417` lists the SCIM routes with `SCIMToken` auth, not a blanket exemption. | e2e tests need a built server; not run here ("pending e2e VM"). |
| #3462 Restore/migrate at scale | FIXED | `server/admin/backup_restore_scale_test.go:65` `TestScale_BackupRestoreMemoryBoundedAndRoundTrip` (rig `scripts/migrate/scale-check.sh`, SCALE-OPS-1): two sizes, fails if peak RSS grows with row count, and with a Postgres DSN also moves SQLite to PostgreSQL and back and compares every table. | The test is opt-in (`KEYORIX_SCALE_TESTS=1`, builds the server, about 500k audit rows) and SKIPs by default; I did not run it, so what it found or fixed is not checked here. |
| #2934 SAML ACS oracle (a) false positive; SSO sessions record r.RemoteAddr | FIXED | Part 1: the SAML fixture subject is deterministic (`server/faultops/zz_saml_acs_op_test.go:193-233`, #2910). Part 2: `server/http/handlers/saml.go:80` and `sso.go:138` now pass `clientIP(r)`. `TestCompleteSAML_SessionRecordsCanonicalClientIP`, `TestCompleteSSO_SessionRecordsCanonicalClientIP` (`server/http/handlers/sso_session_client_ip_test.go:48,74`) and `TestCompleteSAML_SessionRecordsForwardedClientIPBehindTrustedProxy` pass. | |
| #2823 secrets-crud.spec.ts recycle-bin step flaky | FIXED | `web/e2e/real/secrets-crud.spec.ts:216-237`: the assertions are scoped to the Recycle bin section (heading with `exact: true`), and the row assertion waits with `toHaveCount(1, ...)`. | Read only; no browser in the sandbox. |
| #3328 flake: FuzzCrossReplicaOps seed#0 role-grant commit-order mismatch | NEEDS DECISION | No code change targets it. The last 10 scheduled "Cross-replica race tests (Postgres)" runs (2026-11-04 to 11-13): 8 green, 2 red (11-07 run 42367720758, 11-09 run 42624893497), and both reds fail `TestAuditLongReaders_RollingRewalkDoesNotHoldOneSnapshot`, not this test. `FuzzCrossReplicaOps -count=20` on Postgres passes 20 of 20 here (tree `77a7c2576b95`). | Question: close as not reproduced, or keep for the cross-replica fuzzer owner? Separately, `TestAuditLongReaders_RollingRewalkDoesNotHoldOneSnapshot` failed 2 of the last 10 nightly Postgres runs; I found no issue for it (audit area, OPT-AUDIT-RT-1). |
| #3185 nightly failure on main: is it still red? | FIXED | Scheduled `ci.yml` runs: 2026-11-13 run 43401834881 success (`1856a6b6d28d`), 2026-11-12 run 43194997520 success (`c6ad8a7dcede`). The last red was 2026-11-11 run 42994975630. | Green twice in a row. The bot issue stays open until closed by hand. |

## Group 3: docs, contract and posture

| Issue | Verdict | Evidence | Note |
|---|---|---|---|
| #3449 Docs nits from the v0.96.0 release review | NEEDS DECISION | Item 4 (CA vs `tls.cert_file`) is done: `docs/SELF_HOSTING.md:740-743`. Item 1 (version pin ~239): the clone line now pins a release tag with a reason (`SELF_HOSTING.md:29`, `v0.96.3`), so the original line moved. Items 2 and 3 cannot be checked: `docs/UPGRADING.md` writes release versions with `v` and chart versions without, which looks deliberate, and "names of the control tests cited in the release docs" names no file. | Question: close this issue with this audit as the record, or name the remaining nits. |
| #3941 Contract text for users `?filter=inactive` | FIXED | `server/http/handlers/openapi.yaml:5496`, `server/proto/keyorix.proto:540-541`, `server/proto/pb/keyorix.pb.go:2558` and `web/src/types/api-generated.ts:12458` all say a never-logged-in account counts once it is 30+ days old (judged by its creation date). | Also checked, as asked. |
| #3450 Suspend dialog cannot show where a secret is synced | NEEDS DECISION | Still a gap: `rg` finds no cluster/target report-in anywhere in the server, proto or docs. | Design questions from the issue: opt-in vs default, what an agent may report (no values), staleness, audit. Feature, not a defect. |
| #3455 JSON responses: UTC at the source; evaluate encoding/json/v2 | OPEN | Still the reflective walk with a pre-scan: `server/http/handlers/httpx/response_time_utc_scan.go` (`needsUTC`). No `GOEXPERIMENT=jsonv2` evaluation exists in the tree. | Repro: run the server in a non-UTC zone; every JSON response walks the full value. Low priority perf; owner is the storage owners (convert at source). |
| #2895 ADR-112: 14 settings that cannot be renamed mechanically | NEEDS DECISION | Row 14 was renamed (#2899, `sso.providers[].insecure_trust_saml_asserted_email`). The other 13 stay registered under their current names (`internal/config/insecure_settings_registry.go:342-352`), all 14 are tracked by `TestInsecureSettingsRegistry_EveryIssue2895RowIsRegistered`, and the sweep test refuses a new unregistered weakening. | Questions for Andrei, unchanged from the issue: (1) are the polarity inversions (rows 1, 2, 3, 6, 7, 11) worth inverting, given the alias mechanism does not invert; (2) for the shape changes (rows 4, 5, 8, 9, 10, 12, 13) add a new boolean or stay derived-only. |
| #2892 ADR-115: fold improvements from closed #2628 | OPEN | `docs/adr-115-local-audit-journal.md` is `Parked (2026-10-13)` with no amendment from #2628. #2628 and the prototype #2758 are both closed. | Deferred by its own terms: do it in the session that revives the journal. Not actionable now; keep open as a pointer. |
| #2900 Key-set manifest | FIXED | `internal/keyfiles/manifest.go` (generation id, per-file hash and generation, atomic write), verified at boot by `VerifyKeySetConsistency` (`internal/keyfiles/consistency.go:275-282`, `server/main.go:515`). The mtime heuristic is gone (`rg keySetMtimeTolerance` finds nothing). `TestEveryKeyMaterialWriterUpdatesTheManifest` (`internal/keyfiles/manifest_writers_structural_test.go:118`), `TestReconcile_PreManifestCompleteSet_IsAdoptedOnce`, `TestReviewKF_ManifestFromAnotherGeneration_Refused` pass; writer tests in `internal/encryption/keyset_manifest_writers_test.go`; restore path in `server/admin/restore_keyset_manifest_test.go`. | Acceptance criteria 1 to 6 each have a test or a code location. |

## Verified earlier today by PLANNER-11140103 (rows copied, not rechecked)

Source: `~/proj/prompts/reports/SESSION-PLANNER-11140103.md`. The brief says not to recheck these.

| Issue | Verdict | Evidence |
|---|---|---|
| #3147 | FIXED | `internal/core/break_glass.go` `ListBreakGlassActivationsForCaller` returns the caller's own rows. |
| #2868 | FIXED | `web/src/types/__tests__/openapiDrift.test.ts` `allowKey(path, kind)`. |
| #3460 | FIXED | `web/nginx.conf` `/health` is backend-aware. |
| #2803 | FIXED | `RevertAccessReviewItemClaim` no longer exists. |
| #3453 | FIXED | `scripts/demo` curl sites use `-H @file`. |
| #3830 secretenv bootstrap and Vault tokens bypass the `*_FILE` snapshot | FIXED | Verified by PLANNER-11140103 in an earlier plan; no evidence line in its report. |
| #3914 residual host-zone time sites | FIXED | Same. |
| #3426 failed webhook delivery logs the full channel URL | FIXED | Same. |
| #3429 gRPC failed-auth IP limiter sweeps its whole map | FIXED | Same. |
| #2925 posture labels a deprecated-name setting as shipped-default | FIXED | Same. |
| #3742 `[demo]` encryption init blames a live server | FIXED | Same. |
| #3736 `[demo]` audit search `--actor` never matches a machine identity | FIXED | Same. |
| #3741 `[demo]` break-glass list shows the user as a bare ID | FIXED | Same. |
| #3941 | FIXED | Rechecked above (Group 3). |
| #3523 admin init creates a SQLite file when PostgreSQL is intended | OPEN | The fix is in open PR #4189 (PILOT-ADMIN-OPS-1, `server/admin`, not mine to touch). It is not on `origin/main` yet: close after #4189 merges. |

Rows with "no evidence line" rest on the planner's word; a reader who wants the file:line should ask PLANNER-11140103.

## Fixes in this PR

None. Every OPEN or undecided item is one of: an API-shape or product decision (#3444, #3450, #2895),
a CI or `.github` change (#3445), another session's files (#3523 in `server/admin`, #3454 read path),
an open leftover with no small unowned fix (#3455, #2892), or a flake with no reproduction (#3328).
The "at most 4 test-first fixes" allowance was not used.

## Methods and limits

- Every FIXED row names code or a test on `origin/main`; tests marked "pass" were run on this tree.
- Not run: the e2e journeys (#3463, need a built server and the e2e VM), the opt-in scale test (#3462),
  and the web specs (#2823, no browser in the sandbox). Their rows rest on reading the code and tests.
