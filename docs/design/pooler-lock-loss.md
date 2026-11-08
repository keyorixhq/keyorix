# Advisory-lock loss behind poolers and failovers

Status: design note (POOLER-LOCKLOSS-1, 2026-10-23). Operator-facing rules live in
[postgresql-poolers.md](../postgresql-poolers.md); this note records the holder
inventory, the failure modes per deployment shape, the detection options and what
was chosen.

## Premise check

The backlog item (STORAGE-FOLLOWUPS-1, "POOLER-LOCKLOSS-SESSION") said that losing a
session-scoped lock (direct connection, PgBouncer session mode) goes undetected. That
was true before LOCKLOSS-SESSION-1 and is no longer true on main: every lock held across
statements in `internal/storage/store` (named, scheduler, bootstrap, audit-checkpoint,
audit index build), the server-presence lock and the single_writer holder lock are
watched in every pooler mode (INV-STORAGE-session-advisory-lock-loss,
`internal/storage/INVARIANTS.d/`). The backlog check grepped `docs/INVARIANTS.md` and
`internal/storage/store/INVARIANTS.md` only and missed the fragment and
`docs/postgresql-poolers.md`.

Checking each holder against the code found two that were not watched, and an invariant
line that was wrong about one of them:

- `serverguard.Exclusive`, the exclusive form of the presence lock. The invariant said
  only a test hook held it. In fact every `keyorix-server admin` command that needs the
  database to itself holds it for its whole run (`server/admin/admin.go`
  `acquireDatabaseLock`, 23 call sites): encryption init/rotate/rotate-kek/migrate-provider,
  restore, migrate, recover-admin, recovery-key, login-lockout, the audit commands,
  validate, diagnose and `backup --exclusive`. With
  `storage.encryption.key_dir_lock: database`, it is the only thing that keeps a replica
  off the key files during a rotation or restore ([multi-replica-keys.md](../multi-replica-keys.md)).
- The key-initialisation lock (`serverguard.WithKeyInitLock`, key 872343). It covers
  first-boot key generation and DEK-rotation crash recovery under
  `key_dir_lock: database`.

Both are fixed in the same PR as this note (see "Chosen").

## What takes advisory locks, and what each protects

| Lock | Key | Held for | Form (direct / pgbouncer-session; pgbouncer-transaction) | Protects | On loss (after this PR) |
|---|---|---|---|---|---|
| Server presence (`serverguard.Presence`) | 872342 shared | server lifetime | session lock on a dedicated connection; xact lock in a pinned transaction | keeps state-changing admin commands out while a server runs | log, metric, graceful shutdown, exit 1 |
| Admin exclusive (`serverguard.Exclusive`) | 872342 exclusive | one admin command | as above | keeps servers and other admin commands out; under `key_dir_lock: database`, the key files too | log, metric, the command stops with exit 1 (**new**) |
| Key initialisation (`WithKeyInitLock`) | 872343 | first-boot key generation and crash recovery at start-up | as above | one replica writes the shared key files at a time | log, metric, start-up refused (**new**) |
| Migration | 872341 | schema migration | session lock; xact lock inside the migration transaction | one replica migrates | the migration runs on the lock's own connection, so its next statement fails |
| single_writer holder | fixed | server lifetime | session lock, polled every 250 ms | one writer for the cached security tables | log, metric, graceful shutdown, exit 1 |
| Named lock (`WithNamedLock`) | per key | one check-then-act section | session lock on its own pool; xact lock in a pinned transaction | cross-replica check-then-act (invitations, SCIM, project members, SoD, access reviews, ...) | section ctx cancelled with `ErrAdvisoryLockLost`, error returned |
| Scheduler job lock | per job | one tick | as named | one replica runs a job tick | the same; the tick is logged as failed |
| Bootstrap, audit-checkpoint, audit index build | fixed | one section | as named | first-admin bootstrap; checkpoint signing; one index build | the same |
| Audit chain append, cache epoch, role-permission generation, retention anchor, suspend marker | fixed | **one transaction** | `pg_advisory_xact_lock` inside the protected transaction itself | serial order of the chain and counters | cannot outlive its writes: losing the backend aborts the transaction, so nothing to detect |

Two fences in the protected data back up the locks for the highest-value cases:

- **DEK epoch** (`internal/encryption/dek_epoch.go`, #3337): `system_metadata.dek.epoch`
  holds the current DEK's fingerprint, or `rotating:<old>` while a rotation's sweep
  runs. A server whose DEK is not the recorded one refuses to start, and encrypted
  writes are refused while the epoch is fenced. A replica that slips in during a DEK
  rotation because the admin lock was lost is stopped by this, independent of any lock.
- **single_writer write epoch** (`internal/solewriter`): the fenced tables carry a
  write epoch that a second writer's writes change, so foreign writes are noticed.

## Failure modes per deployment shape

How a held lock disappears, and whether the client can notice:

| Shape | Lock form | How the lock is lost | What the holder sees |
|---|---|---|---|
| Direct connection | session lock | `pg_terminate_backend`, PostgreSQL restart or crash, a failover (the old primary's backends die), a TCP partition PostgreSQL notices first, `idle_session_timeout` on an idle lock connection | the next statement or ping on the lock connection fails |
| PgBouncer `session` | session lock on the server connection pinned to the client | as direct, plus a PgBouncer restart, and `client_idle_timeout` closing an idle lock connection | PgBouncer closes the client connection when its server connection dies, so the same as direct; `server_reset_query = DISCARD ALL` clears a disconnected client's locks before reuse |
| PgBouncer `transaction` (`pooler: pgbouncer-transaction`) | xact lock inside a transaction kept open | as session, plus `idle_transaction_timeout`, `transaction_timeout` (PgBouncer and PostgreSQL 17+) ending the open transaction | the client connection is closed: the next ping fails. PostgreSQL's own timeouts are switched off for the lock transaction (`SET LOCAL`) |
| PgBouncer `transaction` **undeclared** | session lock in autocommit | not lost, worse: the lock stays on a server connection other clients share, so two replicas can both "hold" it and an unlock may run elsewhere | nothing; the start-up check (`refuseUndeclaredTransactionPooler`) refuses when two connections share a backend |
| PgBouncer `statement` | — | multi-statement transactions are refused | not supported |
| RDS Proxy | session locks pin the client to one backend | the pinned connection's 24 h maximum life, `IdleClientTimeout`, a proxy failover | undocumented whether the proxy closes the client connection or reconnects it to a new backend; a silent reconnect is **not** detected by a liveness ping |
| Patroni (or any) failover behind a VIP / HAProxy / DNS | as the shape in front | every backend on the old primary ends | connections are closed (or reset), so the ping fails; the new primary has no locks, so another replica can take them at once |
| PgCat, Odyssey, Supavisor, pgpool-II | depends on mode | pooler-specific timeouts, server lifetime, reset queries | not tested; see the table in postgresql-poolers.md |

The overlap window: from the moment a lock is lost until its holder notices, another
replica can take it. With the liveness ping that is up to one interval plus the ping
timeout (5 s + 5 s by default), and nothing in the ping design closes it: the error
makes the overlap visible, it does not prevent it.

## Detection options

| Option | What it detects | What it misses | Cost |
|---|---|---|---|
| **A. Liveness ping of the lock connection** (current: `config.WatchPinnedLockConnGated`) | the lock connection died (every shape above that closes the client) | a lock released while the connection lives (nothing in Keyorix does that); a pooler or proxy that silently reconnects the client to a new backend; the overlap window | one empty statement per held lock per interval; one goroutine per lock |
| **B. Holder re-validation**: `SELECT ... FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted AND <key>` instead of the empty ping | A, plus a silent reconnect (the new backend holds nothing) and a lock released on a live connection | the overlap window | a `pg_locks` read per check (it briefly takes the lock-manager partition locks; fine at one per lock per interval, not per request). In the transaction shape it must go over the simple query protocol, as the lock statement does, so the long-open transaction keeps no snapshot |
| **C. Lock-token heartbeat**: a lease row (holder id, expiry) the holder renews, as the scheduler lease already does (`local_scheduler_lock_lease.go`) | a holder that stopped renewing | still has a window (the lease length); depends on clocks; a write per heartbeat | a row write per renewal per lock; a schema row per lock |
| **D. Fencing token in the protected data**: a monotonic epoch the holder reads under the lock and every protected write checks with compare-and-set in its own transaction | closes the overlap: a stale holder's write is refused even inside the window | nothing for the writes it covers | a schema and code change per protected write path; only worth it where an overlap is unacceptable. Already done for DEK rotation (DEK epoch) and single_writer (write epoch) |
| **E. Transaction-scoped lock inside the protected transaction** | nothing to detect: lock and writes end together | — | only possible when the critical section is one transaction on one connection; not for sections that span many transactions, call out to KMS, write key files or run a scheduler job. Already used for the audit chain and the counters above |

## Chosen

1. Keep A as the baseline for every lock held across statements. It covers every
   supported shape (direct, PgBouncer session, PgBouncer transaction): in all of them a
   lost lock closes the client connection.
2. In this PR: close the two holders A did not cover.
   - The admin exclusive lock is watched (`serverguard.Exclusive.Lost`), and
     `acquireDatabaseLock` stops the command with exit status 1 when it closes
     (`server/admin/lock_loss.go`). Stopping part-way is what a crash does, and every
     state-changing admin command already has to survive that: DEK rotation has crash
     recovery with a redo marker (ADR-010 addendum), and an open transaction rolls back
     with the connection. Running on beside a server that got in is what it must not do.
   - The key-initialisation lock is watched while its function runs and checked once
     more when it returns (the function usually finishes inside one ping interval). A
     loss makes `WithKeyInitLock` return an error, so the replica refuses to start
     instead of serving with keys that may not match the files a sibling wrote meanwhile.
   - Every loss is counted in `keyorix_advisory_lock_lost_total{lock}` as well as logged,
     so per-section losses (which leave the server running) can be alerted on.
3. Next, if another pooler or proxy is to be supported: replace the empty ping with B
   (holder re-validation). It is a small change in one place (`WatchPinnedLockConnGated`
   and the key-init final check) and closes the silent-reconnect gap that RDS Proxy may
   have. Not done here: no supported shape needs it, and it changes the query every held
   lock sends, which should be measured through PgBouncer transaction mode first.
4. D only where an overlap is unacceptable; the two cases where it is (key rotation and
   single_writer) already have it. Named-lock sections should each re-check their
   precondition inside their write transaction or rely on a constraint; the audit
   below lists, section by section, which ones do.
5. C is not recommended: it adds writes and clock dependence and still has a window.

Not changed, and why:

- **Live `admin backup` presence lock.** A live PostgreSQL backup holds the presence
  lock shared under `key_dir_lock: database` so a rotation cannot start meanwhile.
  Stopping it like the other admin commands (exit at once) would leave a partly
  written output file (it is written in place, not renamed into place). Since
  ADMIN-TAILS-1 it acts on Presence.Lost itself instead: writes to the archive stop,
  the snapshot reads are cancelled, the partial file is removed and the backup fails
  with the reason (`TestAdminBackup_Postgres_RealPresenceLockLost_NoArchive`,
  `TestAdminBackup_Postgres_PresenceLostMidWrite_RemovesTheArchiveAndFails`).
  SERVERGUARD-LOCK-TAILS-1 made this hold at every point up to the close (the lock is
  looked at again after the file is closed) and on the exclusive path too (SQLite,
  `--exclusive`), where the stop is an `os.Exit`: the archive's removal is registered
  before the first byte and runs before the exit (`onLostDatabaseLock`). The error says
  the backup is not usable (`TestAdminBackup_SQLiteLockLost_NoArchiveAndNonZeroExit`,
  `TestAdminBackup_Postgres_LivePresenceLost_NoArchiveAndNonZeroExit`: before the first
  byte, mid-stream, after the last byte before close).
- **The overlap window itself** for named and scheduler locks: closing it needs D (or E)
  per section. The audit below says which sections need it.

## Overlap-window audit (SERVERGUARD-LOCK-TAILS-1)

For each section that runs under a lock held across statements, the table says what a
second holder could do inside the overlap window after a silent loss. A second holder is
another replica that took the same key while the first one has not yet noticed. The table
also says whether anything other than the lock already prevents the bad end state.

"Out of the transaction" means the check reads through `c.storage` (autocommit) and the
write runs in a later transaction. That is not a re-check: two holders pass their checks,
then write disjoint rows (write skew). The schema has no foreign keys
(`internal/storage/testdata/schema_epoch/`).

This is a code-reading audit: no red test was run for the uncovered rows. Each one names the
test it would take.

| # | Section (call sites) | Protects | A second holder in the window could | Already covered by | Verdict |
|---|---|---|---|---|---|
| 1 | `last-admin-guard`, deactivation: `account_state.go` SuspendUser; `users.go` UpdateUser (deactivate), DeleteUser; `scim.go` UpdateSCIMUser (deactivate), DeprovisionSCIMUser; `migrate_user_to_machine.go` | at least one live global admin (#1646) | deactivate admin A while another holder deactivates admin B: each guard sees the other admin as surviving, so the install is left with **zero admins** | nothing: `guardLastAdminDeactivation` reads out of the transaction; the write transaction locks only the target user | **not covered, cheap** (see below) |
| 2 | `last-admin-guard`, group side: `rbac_management.go` RemoveRoleFromGroup (global, and access-review revoke); `project_members.go` group project-admin guard locks; callers DeleteGroup, RemoveUserFromGroup, SCIM group removals | the same, plus a project admin for every project the group administers | remove two admin groups or the last members of two groups: zero global or project admins | nothing: the guards read out of the transaction; the deletes take no shared row lock | **not covered, cheap** (same change as row 1) |
| 3 | `last-admin-guard`, direct global admin-role removal: `rbac_management.go` removeGlobalAdminRoleIfApplicable; `role_set_replace.go` (global branch) | the same | nothing against another row-3 holder; zero admins together with a row-1 or row-2 holder | `RemoveGlobalAdminRoleGuarded` (`local_rbac.go`): check and delete in one transaction with FOR UPDATE on every global admin grant row and its holders | **covered against itself**; not across sections until rows 1–2 take the same row locks |
| 4 | `project-admin-guard`, last project admin: `rbac_management.go` withUserRoleRemovalGuards and RemoveRoleFromGroup (project scope); `project_members.go` RemoveProjectMember; `role_set_replace.go` (project branch, swap); `break_glass.go` RevokeBreakGlassActivationAtomic | at least one project-level `roles.assign` holder | two removals of two different project admins: zero project admins (a global admin can re-add one) | nothing: `guardLastProjectAdmin` reads out of the transaction; the removals are plain deletes | **not covered, cheap** (row 1's change, scoped to the project); low value |
| 5 | `project-admin-guard`, break-glass activate: `break_glass.go` | an activation's grant never lands after a revoke reported success (#2722) | nothing | record and grant in one transaction (#3109); `uniq_break_glass_active_project_user`; the revoke is one transaction with a conditional update | **covered** (the lock is no longer load-bearing) |
| 6 | `sod-grant:user`: `rbac_management.go` AssignUserRole, SSO grant, baseline backfill, withOrderedUserSoDLocks; `jit_access.go`; `invitations.go` access-request finalize; `groups.go` AddUserToGroup; `role_set_replace.go` | separation of duties: no principal holds a policy-toxic permission set (#419) | grant two individually clean roles to one user concurrently: an **SoD-conflicting pair** | only a duplicate of the same grant (`user_roles_pkey`); the SoD check reads out of the transaction, or (`role_set_replace.go`) inside it with no shared row lock | **not covered, accepted** (below) |
| 7 | `sod-grant:group`: `rbac_management.go` AssignRoleToGroup; `jit_access.go` group grant with expiry | SoD across every group member (#1780) | a group grant and a direct grant to a member: a toxic pair | duplicates only (`group_roles_pkey`) | **not covered, accepted** (below) |
| 8 | `sod-grant:machine`: `machine_token.go` AssignMachineRole; withMachineRoleRemovalGuards | SoD on machine credentials | AssignMachineRole: a toxic pair. The removal section cannot create a conflict | duplicates only | grant: **not covered, accepted** (below); removal: nothing to protect |
| 9 | `sod-grant:group`, RestoreGroup: `groups.go` | a non-global admin cannot restore a group carrying an admin role its ceiling check never saw (#2455) | an admin-role grant lands on the deleted group after the restore read its roles | nothing | **not covered, accepted** (below); low |
| 10 | `dual-control-approval`: `invitations.go` | M-of-K: the grant is made exactly once, at the K-th distinct approver | (a) a double grant or a double finalize; (b) two approvers straddling K both record a partial approval, so the request stays pending and lapses | (a) `user_roles_pkey`, the conditional `UpdateAccessRequest … WHERE state = 'pending'` with a RowsAffected check, `ux_access_request_approver`; (b) nothing | (a) **covered**; (b) **not covered, accepted** (below; fails closed: availability only) |
| 11 | `project-membership`: `membership_lifecycle.go` invite, TransitionMembership | a revoked membership never has a live grant (#2657, #2659); one active onboarding per project and user | the activation's state change commits, a revoke runs and succeeds, then the activation's grant lands: a **revoked member with live access** | the duplicate onboarding by `uniq_project_memberships_active`; not the grant against the revoke (the state change and the grant are separate transactions) | **not covered, cheap** (move the state change into the grant and removal transactions) |
| 12 | `secret-dependency-graph`: `secret_dependencies.go` | the dependency graph stays acyclic (INV-CORE-31) | add A→B and B→A concurrently: a **cycle** | duplicates by `idx_secret_dep_edge`; not cycles (FOR UPDATE on existing edges does not block a new edge) | **not covered, cheap** (a BEFORE INSERT trigger that takes a per-project transaction lock and checks reachability; no client round trip) |
| 13 | `environment-secret-guard`: `secrets.go` CreateSecret, CreateFolder, RestoreSecret; `secret_suspend.go` resume; `catalog.go` and `local_secrets.go` DeleteEnvironment | no active secret or folder under a deleted environment | a create passes its environment check, DeleteEnvironment counts zero and deletes, then the insert commits: an **orphaned active secret** | nothing: the create transaction re-checks only the project row; DeleteEnvironment counts, then deletes | **not covered, cheap** (FOR SHARE on the environment row in place of the project lock; delete first, then count, in one transaction) |
| 14 | `WithBootstrapLock`: `auth_bootstrap.go` | one first-admin seed | nothing | one transaction; the loser hits unique `permissions.name`, `uniq_roles_name_folded`, `uniq_projects_name_active` | **covered** |
| 15 | `WithAuditCheckpointLock`: `audit_checkpoint.go`, `audit_verify_state.go`, `audit_verify_incremental.go`, `audit_key_transition.go` | the audit high-water mark never moves back; the signed verify state never loses a recorded failure | the slower holder writes a lower high-water mark after the faster one, so a truncation of the newest events goes unseen; a lost update of the verify state can drop a sticky failure | `CompareAndSetSystemMetadata` (AUDIT-HIGHWATER-CAS-1): `advanceAuditHighWater`, the key-transition re-sign of the mark and `saveAuditVerifyState` write only over the value they read. A lost mark write re-reads the floor and skips (floor already at cp) or retries once; a lost state save is redone once over the reloaded row by `updateAuditVerifyState` (other state writers fail and their next run retries). Proved by `TestAuditHighWaterCAS_SlowerHolderNeverLowersTheMark` and `TestAuditVerifyStateCAS_LostUpdateKeepsRecordedFailure` (two cores, separate pools, SQLite and PostgreSQL) | **covered** |
| 16 | `WithSchedulerLock`: `server/scheduler_run.go` (about 20 jobs) | one replica per tick | run the same tick twice | per job: see "Scheduler jobs" below | **audited per job**: one job can leave a credential out of step (auto-rotation with a backend), one can open a duplicate campaign (recertification), the rest are safe or only repeat output |
| 17 | audit list index build: `audit_list_indexes.go` | one builder | the second builder drops the first one's in-progress index as invalid, and the build retries | catalog name uniqueness, the validity check after the build | operational only; accept |

What the uncovered rows need, none of it adding a round trip to a request path:

- **Rows 1, 2 and 4** (last admin): take `RemoveGlobalAdminRoleGuarded`'s FOR UPDATE on the
  global (or project) admin grant rows as the first statement of every deactivation and
  removal transaction. Re-check survival there, and drop the out-of-transaction guard read
  it replaces. That is about ten call sites in `internal/core`.
- **Row 11** (membership): move the membership state change into the grant and revoke
  transactions.
- **Row 12** (dependency cycle): add the trigger.
- **Row 13** (environment guard): add FOR SHARE on the environment, and in DeleteEnvironment
  delete first, then count, in one transaction.
- **Row 15** (audit high-water and verify state): done, `CompareAndSetSystemMetadata` in place
  of the upsert (AUDIT-HIGHWATER-CAS-1).
- **Rows 6–9** (SoD): accepted for now, see below. The fix, if it is ever wanted: move the
  SoD read into the grant transaction under `pg_advisory_xact_lock` on the same key
  (option E), across about twelve grant paths.
- **Row 10b**: accepted for now, see below. The fix: an `approvals_count` updated with
  `RETURNING`.
- **Row 16**: audited, see "Scheduler jobs" below.

Each fix is proved with the cross-replica fixtures in
`internal/core/concurrency_check_then_act_exempt_review_postgres_test.go` (`newCTAReview`):
replica A's `WithNamedLock` is replaced by a pass-through hook to model the silent loss,
then the two replicas race.

### Accepted window: SoD grants and dual-control straddle

Decision (2026-11-08): rows 6–9 and 10b stay as they are for now. Restructuring them is
option E across about twelve grant paths, and the exposure does not justify it yet.

What is accepted, for the overlap window only (from a lost lock until the holder notices,
at most one ping interval plus the ping timeout, 5 s + 5 s by default):

- **Rows 6–9.** Two grants to the same principal (or to a group and one of its members)
  can each pass the SoD check and together form a policy-toxic set. On RestoreGroup, an
  admin-role grant can land on the group after the restore read its roles.
- **Row 10b.** Two approvers straddling K can both record a partial approval. The request
  stays pending and lapses, and has to be requested again. It fails closed: nothing is
  granted.

Why that is acceptable: it needs a lost advisory lock and two concurrent authorised
requests inside the same few seconds, so nobody can trigger it without already holding
the right to grant. Rows 6–8 also leave a detectable end state: the SoD register
(`DetectSoDViolations`) reports the toxic pair in the compliance digest and the evidence
pack, where an administrator can remove it. Row 9 has no such report.

Reopen this if the window grows (a longer ping interval, or a pooler that reconnects
silently, see option B), or if SoD becomes a control a customer needs enforced at grant
time with no exceptions.

## Scheduler jobs (row 16, FU-SERVERGUARD-SCHED-1)

For each of the 20 jobs in `schedulerStarts` (`server/main.go`): what happens if two replicas
run the same tick in the overlap window. This is a code-reading audit: no two-replica race
was run. The two fixes at the end have red/green tests.

A holder that loses its lock has its context cancelled within the window, so most work it
has not started fails on its own. What matters is what the two holders do before that, and
what a cancelled tick still emits. Audit rows are written on a detached context
(`store.auditWriteContext`), so a cancelled tick can still write them.

| Job | Two runs of one tick | Stopped by | Verdict |
|---|---|---|---|
| `auto_rotation`, no backend | each run stores a version: two rotations, the last stored value is current | `uniq_secret_versions_node_version` and the retry give each its own number; nothing outside Keyorix changes | safe, one extra rotation |
| `auto_rotation`, password-set backend (PostgreSQL, MySQL, Redis, MongoDB) | both set a password upstream and both store. Upstream ends on the last *apply*, Keyorix on the last *store*. If those differ, Keyorix holds a password that does not work, with no `DRIFT` audit row | nothing: `rotationBackendLock` is per process | **not idempotent**: credential out of step until someone rotates it |
| `auto_rotation`, generate-upstream backend (AWS IAM, GCP, Azure) | each run mints a key and deletes the keys it listed, which can include the other run's new key. Keyorix can end up storing a deleted key | nothing, as above | **not idempotent**: same outcome |
| `evidence_delivery` | a second signed pack, file and webhook, and a second audit row. Each pack is complete and self-consistent | names are per second. Two runs in the same second overwrite each other's file (`O_TRUNC`, no rename), only on a shared `output_dir`, and pack and signature can then come from different runs | safe, repeats output |
| `recertification`, `auto_open` | two open campaigns for one project, each needing review. Reminders repeat | nothing: check-then-create, no unique index on open campaigns | **not idempotent**: duplicate review work, no access change |
| `compliance_digest` | a second broadcast | nothing | repeats output |
| `rotation_reminder`, `expiry_reminder` | one notification; the summary audit row repeats | `uniq_notifications_unread_reminder`; a refused insert sends nothing out of band (#488) | idempotent |
| `certificate_expiry`, `license_expiry`, `read_quota_alerts` | duplicate notification and its out-of-band delivery | nothing: the index covers only the two reminder types above | repeats output |
| `break_glass_review_reminder` | a second round of an already repeating reminder and audit row | nothing | repeats output |
| `anomaly_detection` | duplicate alerts are possible on PostgreSQL, and each is announced | the dedup in `CreateAnomalyAlert` is one transaction but is not serialised on PostgreSQL. A high-water mark moved back only re-scans | repeats output |
| `recover_admin_alert` | the in-flight batch is alerted twice | at-least-once by design. The mark's check-then-set is not atomic, so it can move back: more repeats, never a skipped event | repeats output |
| `jit_access_expiry` | each grant goes once; a run that read the rows before the other deleted them writes `role.expired` / `share.expired` again | row deletes | idempotent for access, audit rows can repeat |
| `dynamic_secret_sweep` | each credential goes once; `dynamic_lease.revoked` can repeat. A target failure in the second run can mark a revoked lease `revoke_failed`, and the next sweep clears it | revokes are no-ops when already gone (`DROP ... IF EXISTS`, `ACL DELUSER`, not-found ignored) | idempotent |
| `retention_purge`, `data_retention`, `login_attempt_prune`, `mfa_stepup_grant_prune` | the second run deletes nothing; its audit row is written only when it removed rows | delete by cutoff | idempotent |
| `audit_owed_backfill` | each owed row is written once | `ClaimPendingAuditEvent` in the write's transaction | idempotent |
| `audit_checkpoint` | checkpoint and verify state as row 15. The rolling cycle can lose a step and re-walk it | `CompareAndSetSystemMetadata`; a recorded failure stays | idempotent |

Also on the scheduler lock but not a tick: the on-demand full audit verification
(`AuditVerifyJobLockKey`). It is outside this table.

### Fixed here

Both are the case where a cancelled tick did something worse than stop:

- **Auto-rotation** walked the rest of its queue on the dead context. Every secret it had
  not reached got a "started" and a "FAILED" audit row, and the alert channels were told it
  failed. It now stops at the cancellation, and those secrets stay due for the next tick
  (`TestRunAutoRotation_CancelledTickDoesNotTouchRemainingSecrets`).
- **Evidence delivery** turned a collection cut off by the cancellation into a signed
  `DEGRADED` pack, wrote it and audited it as an export. It now stops before delivering
  anything (`TestExportComplianceEvidence_CancelledDuringCollectionDeliversNothing`).

### Left as it is

- **Auto-rotation with a backend** is the one that matters. The fix is cross-replica
  serialisation per (backend, ref), replacing the in-process `rotationBackendLock` (which
  already leaves on-demand and scheduled rotation unserialised across replicas), plus a
  re-read of `last_rotated_at` under it. It needs its own design, and a two-replica test
  with an executor that records the order of applies and stores.
- **Do not detach the store from the cancelled context** to save a value already applied
  upstream, though it looks like the obvious fix. Today a store cancelled after the apply
  writes a `DRIFT` audit row, leaves `last_rotated_at` alone, and the next tick rotates
  again (hourly by default), which repairs it. A detached store could land after the other
  holder's, and would make the silent case above more likely.
- **Recertification**: a partial unique index on open campaigns per project, with a
  duplicates pre-flight. It changes what an on-demand open may do.
- **`compliance_digest` and `AlertNewAnomalies`** could take the same stop-on-cancel check.
  Without it a cancelled digest can broadcast an `INCOMPLETE` headline, and a cancelled alert
  loop can write audit rows that the next tick repeats. Both are noise, so they are left.
- **`certificate_expiry`, `license_expiry`, `read_quota_alerts`**: a unique key would need a
  structured dedup key (`read_quota_alerts.go` explains why the current index cannot
  cover per-secret notifications).

## Evidence

On the real code, against the session PostgreSQL database (kpg) on a direct connection:

- On main, the admin exclusive lock's backend was terminated while the command held it:
  a server then took the presence lock beside the still-running command, and nothing
  reported it (`serverguard.Exclusive` had no loss signal).
- On main, the key-initialisation lock's backend was terminated inside its function: a
  sibling took the lock while the first holder was still in it, and `WithKeyInitLock`
  returned success (`TestPostgres_WithKeyInitLock_LostLockFailsTheHolder` red on main,
  for both lock shapes).
- With this PR the same tests are green: `Exclusive.Lost` closes and the admin command
  stops (`TestAcquireDatabaseLock_LostLockStopsTheCommand`), and `WithKeyInitLock`
  refuses.
- The existing session-shape tests pass at the same commit
  (`TestSessionAdvisoryLock_KilledLockBackend_StopsTheHolder`,
  `TestPostgres_ServerGuard_LostSessionPresenceLockIsReported`,
  `TestGuard_KilledHolderBackend_ClosesLost`, and the transaction-shape
  `*_TransactionPooling_KilledLockBackendIsReported`).

Through PgBouncer (session and transaction mode, backend killed): **pending e2e VM**.
The run is `scripts/pgbouncer-matrix.sh`, which runs every `TestPgBouncer_*` in
`internal/serverguard` (including the new `TestPgBouncer_ServerGuard_LostExclusiveLockIsReported`)
and `internal/storage` through PgBouncer session mode, transaction mode and transaction
mode with prepared statements.
