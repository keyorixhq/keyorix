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
   precondition inside their write transaction or rely on a constraint; this note does
   not audit them one by one.
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
- **The overlap window itself** for named and scheduler locks: closing it needs D per
  section.

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
