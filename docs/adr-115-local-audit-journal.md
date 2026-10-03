# ADR-115: Local append-only audit journal with group fsync

## Status

**Proposed** (2026-10-03). Design only. No code in this PR. Nothing here is
implemented, and no part of it may be described as shipped until the "Measurement
plan" has run and the "Ratification preconditions" below hold.

**Builds on:** ADR-029 (audit hash chain, checkpoints, anchors), ADR-039 (HA
topology), the B3 backup design (`docs/design-b3-backup-v2.md`), the B4 offline
verifier (`docs/design-b4-offline-audit-verify.md`, `internal/auditverify`), and
**PR #2420** (group-commit flusher plus fail-closed audit-before-disclosure).
#2420 was still **open and unmerged** when this was written (`origin/main` =
`46a8b0b7`). On `main` today, every secret read still fires its audit write as
`goSafe(func(){ LogSecretReadWithProject(...) })` and discloses the value without
waiting (`server/http/handlers/secrets_crud.go:306`, `:427`;
`server/grpc/services/secret_service.go:203`). **This ADR takes #2420's
guarantee as the baseline it must preserve.** If #2420 does not merge, this ADR
cannot be implemented as written: there would be no "today's guarantee" to be
equivalent to.

## Context

### The measured problem

The PERF-2 study (PERF kit on `pve01`; its raw data is not in this repo) put
Keyorix at about **10x slower than Vault at 1 client** and about **6.4x slower at
50 clients**, with Vault's file audit device **on**. Turning on Vault's audit
device cost Vault about 25% at c=1 and nothing measurable at c=50.

Keyorix's audit append (#2420 branch, `internal/storage/store/local_audit_chain.go`)
is a database transaction per batch:

1. `pg_advisory_xact_lock(0x4B455941_55444954 /* KEYAUDIT */)` on Postgres. On
   SQLite the write lock is taken at `BEGIN` (`_txlock=immediate`,
   `internal/storage/factory.go:175`).
2. `SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1` (chain head).
3. For each item: compute `entry_hash = computeAuditEntryHash(event, prev)`,
   `INSERT` the `audit_events` row and the `secret_access_logs` row.
4. `COMMIT`. On Postgres this is one WAL flush. On SQLite (WAL,
   `synchronous=FULL`, `factory.go:192`) it is one WAL fsync.

The flusher drains opportunistically (linger 0, the coordinator's decision on
#2420). Batching therefore happens only when requests are already queued, which
means only under concurrency. **At c=1 every read pays one full commit.** On
pve01's measured disk an fsync costs about 9.3 ms. That alone caps one client at
about 1 / 9.3 ms ≈ **107 reads/s**, before any round trips.

### Why Vault's audit is cheap

Vault's file audit device appends a line to a flat file. That is a sequential
write with no lock round trip, no index maintenance and no head read. Vault fails
the request if no audit device accepts the entry, so it does have
audit-before-response at the `write()` level. **To our reading, the file device
does not fsync each entry.** That makes its guarantee "the entry reached the OS
page cache", which survives a Vault process crash but not an OS crash or power
loss. The measurement plan below must confirm this against the exact Vault
version PERF-2 measured. Everything this ADR concludes about c=1 depends on it.

### What must not change

The audit-before-disclosure guarantee from #2420 is non-negotiable: **a secret
value is returned only after its audit record is durable.** "Durable" here means
it survives process crash, OS crash and power loss on the host that
acknowledged it. Tamper-evidence (ADR-029) must also hold for every record at
every point in its life, including while it is in flight.

## Decision

Introduce a **per-node, append-only, hash-chained audit journal** on local disk,
written by one writer goroutine with **group fsync**, and make *journal
durability* the gate for disclosure. An **asynchronous, ordered, idempotent
shipper** then moves journal records into `audit_events` /
`secret_access_logs`, computing the ADR-029 database chain at ship time with
the unchanged algorithm under the unchanged lock.

The feature ships **dark** behind `audit.journal.mode` (`off` | `shadow` | `on`,
default `off`). See "Feature flag and migration".

### 1. Where it sits

The journal is introduced **below the `Storage` interface**, inside
`LocalStorage.logAuditEvent` (#2420's single dispatch point). Today that point
picks between `logAuditEventDirect` (transaction-scoped clone) and
`logAuditEventBatched` (flusher). In journal mode a third path,
`logAuditEventJournaled`, replaces the batched one:

| Caller | `off` (today / #2420) | `on` |
|---|---|---|
| Root `LocalStorage`, any event | flusher → DB commit → return | journal append → group fsync → return |
| Transaction-scoped clone (`WithTransaction`, `RemoveGlobalAdminRoleGuarded`) | direct DB path inside the caller's tx | **unchanged**: direct DB path inside the caller's tx |

Consequences:

- `internal/core` does not change. `emitAudit` / `emitAuditWithAccessLog`
  remain the single choke point (INV-CORE-22). The handlers' fail-closed check
  on `LogSecretReadWithProject`'s error (#2420,
  `TestSecretReadAuditCallSites_CheckedAndNotInGoSafe`) gates on journal
  durability in exactly the same way it gates on DB commit today. It cannot
  tell the paths apart and does not need to.
- **Every** audit event goes through the journal, not only secret reads.
  Fire-and-forget events (`LogSecretCreated`, logins, role changes) still do not
  wait, but they enter the same per-node order. Splitting event types across two
  durability domains would put two independently ordered streams into the
  DB chain with no defined interleaving.
- The transaction-scoped fallback stays on the direct DB path because a journal
  record cannot roll back with the caller's DB transaction. #2420 found no live
  caller of it. It remains correct here: it takes the KEYAUDIT lock, so its rows
  interleave cleanly with shipped rows in the single DB chain. Its rows carry
  NULL journal provenance columns, just like legacy rows.
- `afterAuditEventPersisted` (SIEM forward via `auditForwarder.Forward`, and
  `auditStream.signal()` for gRPC `StreamAuditLogs`) moves to **after ship**, not
  after journal fsync. The SIEM export carries `prev_hash`/`entry_hash`
  (ADR-029 "off-box anchor"), and those exist only once the DB chain position is
  assigned. Forwarding before that would send events without the hashes the
  external anchor relies on.

### 2. Journal format

**Location:** `audit.journal.dir`. No default: `on` and `shadow` refuse to start
without it. It must be on **persistent, node-local storage**: a PVC in
Kubernetes, never `emptyDir` or tmpfs. Startup refuses a directory whose
filesystem `statfs` type is tmpfs/ramfs. That check is best effort and
documented as such: it cannot detect a non-persistent volume backed by an
ordinary filesystem.

**Layout:**

```
<dir>/
  JOURNAL-ID          replica_id (UUIDv4) + created_at + format version; written once, fsync'd, 0600
  LOCK                flock(LOCK_EX|LOCK_NB) held for the process lifetime
  seg-<first_seq:020d>.kxj   preallocated segments (fallocate, default 64 MiB), 0600
```

The directory is 0700. Files are created through
`securefiles.SecureCreateFileHandle` / `SecureOpenBeneath` (openat with
`O_NOFOLLOW` beneath the directory fd), and every create/rename/unlink is followed
by `securefiles.SyncDir`.

**Record framing** (all integers big-endian):

```
magic      u32  = 0x4B584A31 ("KXJ1")
length     u32  = byte length of body
body       [length]byte
crc32c     u32  over magic‖length‖body        -- torn-write detection only, not security
```

**Body:** a TLV encoding with the same length-prefix rule as
`computeAuditEntryHash` (8-byte big-endian length, then bytes) of:

```
"kxj-record-v1"               domain separator
replica_id
seq                           u64, contiguous from 1 per replica_id, never reused
prev_record_hash              hex; the genesis for seq=1 is SHA256("kxj-genesis-v1" ‖ replica_id)
event fields                  every persisted AuditEvent column except id, prev_hash, entry_hash:
                              event_type, user_id, secret_node_id, project_id, ip_address,
                              description, success, event_time (UnixMicro), diff, impersonated_by,
                              acting_as, impersonation, actor_type, machine_identity_id
access_log_present            "0" | "1"
access log fields (if 1)      secret_node_id, secret_version_id, accessed_by,
                              access_time (UnixMicro), action, ip_address, user_agent
record_hash                   hex SHA-256 over every field above, in this order
```

`record_hash` covers **every** persisted field, including `MachineIdentityID` and
the access-log row. Today neither of those is covered by the ADR-029
`entry_hash`. Inside the journal domain this is strictly stronger than the DB
chain. The DB chain's own field set is **not** changed (see §5).

`normalizeAuditEventForHash` runs **before** the record is built: µs
truncation, `ActorType` default and `Success` default. The values in the journal
are therefore byte-identical to what the shipper inserts and what
`computeAuditEntryHash` later covers. `event_time` is encoded as UTC
UnixMicro (INV-STORE-20).

Records never contain a secret value. That is the same rule as `audit_events`
today (`Diff` carries `{"changed":true}`, never plaintext). The canary leak
oracle (`server/http/canary_secret_leakage_fuzz_test.go` lineage) must be
extended to scan journal segments as well as DB rows.

### 3. Writer and group fsync: the durability gate

One writer goroutine per process owns the active segment. It follows the same
shape as #2420's flusher, with an fsync instead of a DB transaction:

```
loop:
  take ≥1 queued request (block), then drain whatever else is already queued (no timer, linger 0)
  for each: assign seq, prev_record_hash, compute record_hash, encode, append to an in-memory buffer
  pwrite(buffer) to the segment at the current offset
  fdatasync(segment)                       -- the group fsync
  complete every request in the batch with nil
  on any write/fdatasync error: complete every request in the batch with the error, then POISON (below)
```

- **Pipelining.** Requests that arrive during an `fdatasync` queue up and become
  the next batch. Under load the batch size self-tunes to "arrivals per fsync"
  with no linger timer. That avoids #2420's finding that sub-5 ms timers cost
  about 6 ms on the benchmark VM.
- **Preallocation.** A segment is `fallocate`d at creation. `fdatasync` on
  already-allocated blocks does not need to journal a size change on most
  filesystems, so the flush is one data flush plus the device cache flush. That
  is the floor for any honest durable write.
- **Rotation.** At the segment size, the writer allocates the next segment and
  `SyncDir`s the directory **before** the first record goes into it. A crash can
  never leave a record in a segment whose directory entry is not durable.
- **Fsync failure poisons the writer.** After a failed `fsync`/`fdatasync`,
  Linux may already have marked the dirty pages clean ("fsyncgate"), so retrying
  the fsync and seeing success proves nothing. Rule: on any write or sync error
  the writer **fails the whole in-flight batch** (none of those reads disclose),
  stops accepting appends, and stays poisoned until the process restarts. On
  restart, recovery (§4) re-reads what is actually on disk. A poisoned writer
  makes the node fail closed (§8).

**Equivalence with today's guarantee.** #2420's guarantee is: *the HTTP/gRPC
handler places a value in the response only after `LogAuditEventWithAccessLog`
returned nil, and nil means the transaction holding the audit row and access-log
row committed.* Written as a statement about the durability of a disclosed
read *r*:

> **G(today):** if *r*'s value left the process, then *r*'s audit and access-log
> rows were in a committed DB transaction, durable under the DB's commit
> durability (Postgres `synchronous_commit=on` on the primary; SQLite
> `synchronous=FULL`).

**G(journal):** if *r*'s value left the process, then *r*'s record was inside a
byte range of the journal for which `fdatasync` returned success, so it is
durable on the node's local disk, and the shipper will eventually commit it to
the DB (§4) under the same chain algorithm.

The proof is by the same structure #2420 relies on. The handler's only route to a
value is through a nil return from `LogAuditEventWithAccessLog`. In journal mode
that nil is sent only after the `fdatasync` covering the record's bytes returned
success. No other code path completes a request with nil: a poisoned writer
completes with an error, and a cancelled context returns `ctx.Err()`. Any
`Storage.LogAuditEvent*` implementation must keep the "nil ⇒ durable" contract.
This becomes a named invariant (proposed **INV-STORAGE-36**, below), guarded by a
fault-injection test that fails `fdatasync` and asserts zero values disclosed.

The two guarantees are **equivalent against**:

- **Process crash, OS crash, power loss.** Both are fsync-durable. A record that
  was written but not acknowledged may survive a crash. It is then shipped as an
  audit record of a read that was never disclosed. That is the safe direction,
  and #2420 already exhibits it (its SIGKILL proof: 7,844 committed vs 7,842
  delivered).
- **Tampering with in-flight records.** Before ship, the record sits in a
  0600 file in a 0700 directory owned by the service user, hash-chained per
  replica. After ship, it is in the ADR-029 chain. Someone who can rewrite the
  journal can already rewrite the process's DB credentials. That is the same
  trust boundary as the DB, and in-flight edits remain *detectable* (§5).

The two guarantees are **not equivalent against loss of the node's disk before
ship.** A record acknowledged into the journal of a node whose volume is then
destroyed is lost. On HA Postgres, a committed row is on the primary and,
depending on the operator's replication mode, on standbys. This is the one real
weakening, and the design bounds it, makes it detectable, and leaves the
strict mode available:

1. **Bounded.** Backpressure (§4) caps unshipped exposure at
   `audit.journal.max_unshipped_age` (default 5 s) and
   `audit.journal.max_unshipped_records` (default 50,000) per node. Past either
   bound, the node fails closed for gating reads.
2. **Detectable, never silent.** Every ship transaction and every heartbeat
   records the node's `durable_seq` (journal head) in the DB (§6). When a node
   disappears, the gap between `durable_seq` and `shipped_seq` is the exact,
   quantified set of acknowledged-but-unshipped records. `verify` reports it as
   a distinct status (§5). Loss turns into a recorded, attributable gap instead
   of an absence.
3. **Opt-out.** Deployments that need audit durability across node loss (for
   example Postgres with `synchronous_standby_names`, where today's commit is
   replicated before the read returns) keep `mode: off`. The ADR does not claim
   equivalence for them, and the posture report (ADR-112 `admin validate
   --posture`, if merged) should flag `mode: on` together with synchronous
   replication as a downgrade.

Against Postgres with asynchronous replication, which is the default and what
ADR-039 documents, a committed-but-unreplicated row is lost on primary failover
too. In that configuration both guarantees are "durable on one host's disk".
The difference is which host.

### 4. Shipper

One shipper goroutine per node ships **its own** journal and never another
node's (except via the offline drain, §6).

**Source of truth for progress is the DB, not a local cursor.** A new table:

```
audit_journal_replicas(
  replica_id        text primary key,
  shipped_seq       bigint not null,   -- highest seq inserted into audit_events
  shipped_hash      text   not null,   -- record_hash at shipped_seq
  durable_seq       bigint not null,   -- journal head the node last reported as fsync'd
  last_heartbeat_at timestamptz not null,
  state             text   not null    -- 'active' | 'draining' | 'retired' | 'forked'
)
```

**Ship transaction**, one per batch (default up to 1,000 records), under the
**unchanged** ADR-029 serialization:

```
BEGIN
  pg_advisory_xact_lock(KEYAUDIT)                       -- same key, same lock; SQLite: _txlock=immediate
  SELECT shipped_seq, shipped_hash FROM audit_journal_replicas WHERE replica_id=? FOR UPDATE
  -- continuity: first record's seq must equal shipped_seq+1 AND its prev_record_hash must equal shipped_hash
  SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1    -- DB chain head
  for each record in seq order:
      entry_hash = computeAuditEntryHash(event, prev)           -- UNCHANGED function, UNCHANGED field set
      INSERT audit_events(..., journal_replica_id, journal_seq, journal_hash)
      INSERT secret_access_logs(..., journal_replica_id, journal_seq)  -- if present
      prev = entry_hash
  UPDATE audit_journal_replicas SET shipped_seq=last.seq, shipped_hash=last.record_hash, durable_seq=?, last_heartbeat_at=now()
COMMIT
```

- **Idempotence and duplicate suppression.** Progress and data commit in the
  same transaction. After a crash at any point, the shipper re-reads
  `shipped_seq` and resumes at `shipped_seq+1`. A record is either in the
  committed batch together with the progress update or in neither. A **unique
  partial index** `(journal_replica_id, journal_seq) WHERE journal_replica_id IS
  NOT NULL` is a second line of defence. Per this repo's Postgres rule
  (CLAUDE.md), a violation of it is **never caught-and-committed**: it returns an
  error, the batch rolls back, and the shipper halts with an alarm, because a
  duplicate seq past the continuity check means two writers share a
  `replica_id` (§6, fork).
- **Ordering.** Per node, records enter the DB chain in strict `seq` order.
  Across nodes, the interleaving is the order in which ship transactions acquire
  KEYAUDIT. That is the same "lock acquisition order" semantics the DB chain has
  across replicas today. The chain orders by `id`, not by `event_time`.
- **No bisection.** #2420's flusher bisects a failing batch so that one poisoned
  item fails only itself. The shipper **must not** do that. A journal record is
  already acknowledged and possibly disclosed, so it cannot be skipped or
  failed. Skipping one would also break continuity. Records are built to be
  unconditionally insertable: `audit_events` and `secret_access_logs` carry no
  foreign keys (`internal/storage/models/models.go:1440`, `:1181`), and
  Description/Diff are truncated by `emitAudit` before they reach storage. A
  record that still fails to insert halts the shipper at that seq with an alarm.
  Lag then grows until backpressure fails the node closed. That is loud, and
  nothing is lost.
- **Partial and torn records (crash recovery).** At startup, before accepting
  appends, recovery scans from the segment containing `shipped_seq+1` (or the
  oldest retained segment) to the end:
  - It verifies framing, crc32c, seq contiguity and the `prev_record_hash` /
    `record_hash` chain.
  - A **torn tail** is accepted and truncated: an incomplete or crc-invalid
    record that is the last thing in the newest segment, followed only by zeros
    or preallocated space. Only an unacknowledged write can be torn, because an
    acknowledged one was covered by a successful `fdatasync`. Its read was
    therefore never disclosed. The truncation is itself recorded as an audit
    event (`audit.journal.torn_tail`, with seq and byte count) once the writer is
    up.
  - **Mid-journal damage is evidence, never repaired**: a crc failure followed
    by valid records, a hash mismatch, or a seq gap. The node refuses to enable
    the writer (fails closed for gating reads), the shipper ships up to the last
    good record, and `verify` reports `journal_corrupt`. An operator must
    intervene with `admin audit-journal inspect`.
- **Segment deletion.** A segment is unlinked only when every record in it is
  ≤ `shipped_seq`, the DB row at its last seq has a `journal_hash` that matches,
  and it is older than `audit.journal.retain_shipped` (default 24 h, for
  forensic cross-checks). Deletion uses `securefiles.SecureDeleteFile` +
  `SyncDir`. A legal hold (INV-CORE-25) does **not** extend journal retention:
  the hold governs `audit_events`, and the shipped DB rows are what it protects.
- **Backpressure.** If the oldest unshipped record is older than
  `max_unshipped_age`, or more than `max_unshipped_records` are unshipped,
  **gating** appends (secret-read audits) fail with `ErrAuditJournalBacklog`.
  The handler then returns 503 (#2420's fail-closed path) and the readiness probe
  reports not-ready so the load balancer drains the node. Non-gating appends keep
  going into the journal, where they wait without disclosing anything, until
  disk headroom (§8) stops them too.

**What the audit API shows while records are in flight.** Every read surface
(`GET /audit/logs`, `/search`, `/export*`, `/rbac-logs`, `/retention`,
`/verify`, gRPC `GetAuditLogs` / `StreamAuditLogs`) keeps reading **only**
`audit_events`. In-flight records are not shown. Merging a node-local journal
tail into API responses was rejected: each replica would return a different
answer depending on which node the load balancer picked, and the records would
have no `entry_hash` yet. Instead:

- `/audit/verify` and `keyorix audit verify --json` gain a `journal` block: per
  `replica_id`, `durable_seq`, `shipped_seq`, `in_flight = durable_seq −
  shipped_seq`, `last_heartbeat_at` and `state`. An auditor sees how many
  acknowledged records are not yet visible, and from which node.
- `GET /audit/logs?consistent=local` drains **the serving node's own** journal
  (waits until `shipped_seq ≥ durable_seq` at request time, bounded by the
  request timeout) before querying. A cross-node "wait for every replica" mode is
  not offered because no node can force another node's shipper.
- Anomaly detection and the alert schedulers read `audit_events` and therefore
  see events up to `max_unshipped_age` late. That bound is documented in the
  anomaly-detection docs.

### 5. Tamper-evidence: two chains, one relationship

- **The DB chain does not change.** `computeAuditEntryHash` keeps its field set,
  encoding and genesis. The checkpoint canonical form (`v1\x00…`), the
  retention anchor (`retanchor-v1`), the checkpoint HMAC key (KEK-derived),
  `WithAuditCheckpointLock`, the high-water mark and the witness file are all
  unchanged. `MigrateAuditChainEncoding` and `refuseIfAuditChainBroken` work
  exactly as before. INV-AUDITVERIFY-02/03 (byte-for-byte canonical agreement)
  are unaffected because neither canonical form changes. The new columns
  (`journal_replica_id`, `journal_seq`, `journal_hash`) are **deliberately not
  added to `entry_hash`.** Adding them would be a hash-format break, and the row
  has no per-row version marker to select an algorithm (see
  `computeAuditEntryHash`'s own "BREAKING CHANGE" comment).
- **The journal chain** is per `replica_id`. It is SHA-256 over the full record
  (§2), from a replica-specific genesis.
- **The relationship is checkable from the DB alone.** For each `replica_id`,
  the shipped rows ordered by `journal_seq` must reconstruct the journal chain:
  for each row, recompute the journal `record_hash` from the row's own columns
  (event fields plus the joined `secret_access_logs` row) and the previous row's
  `journal_hash`, then compare it to the stored `journal_hash`. This makes the
  unhashed provenance columns self-verifying. Editing `journal_seq`, swapping
  `journal_replica_id`, deleting a mid-replica row, or editing a field
  `entry_hash` does not cover (`machine_identity_id`, the access-log row) all
  break the replica chain even though `entry_hash` still verifies. That is a
  **net gain** in tamper-evidence over today for those two field sets, but only
  for rows written in journal mode.
- **In-flight tamper-evidence.** Before ship, a record is protected by its
  replica chain. Any in-place edit of an unshipped record breaks the chain at
  that point, and recovery/shipping refuses to continue past it (§4,
  mid-journal damage). Truncating the **unshipped tail** of a journal on disk is
  the in-flight analogue of ADR-029's tail-truncation residual. It is detected
  because `durable_seq` is reported to the DB on every ship and heartbeat (§6): a
  node whose journal head is below its last-reported `durable_seq` refuses to
  start (`journal_regressed`). The detection window is one heartbeat interval
  (default 1 s), and that is the honest residual.
- **Segment seals (optional, HMAC).** When a segment is closed, the writer
  appends a seal record: `HMAC(K_journal, "kxj-seal-v1" ‖ replica_id ‖ first_seq ‖
  last_seq ‖ last_record_hash)`. `K_journal` is HKDF-derived from the KEK with
  info `keyorix-audit-journal-seal-v1`, domain-separated from the checkpoint key
  and the backup-manifest key (same pattern as INV-AUDITVERIFY-12). A seal
  protects closed segments against a host-level actor who can rewrite and
  re-chain a segment but does not hold the KEK. This is the same trust ceiling
  ADR-029 states for checkpoints.
- **External anchoring (ADR-029).** Checkpoints keep certifying the DB chain
  exactly as today, including the RFC 3161 notary anchor. In addition, the
  `verify --json` `journal` block lists each replica's `(replica_id, shipped_seq,
  shipped_hash)`. A nightly `keyorix audit verify --json` that is appended
  off-box therefore anchors every replica chain as well as the DB chain. A
  later shipped row for that replica must extend that hash.

**Offline verification (`internal/auditverify`).** The B4 verifier gains:

1. a DB-side replica-chain check (the reconstruction above);
2. `admin verify-audit --journal <dir>`, which verifies a journal directory's
   framing and chain, and cross-checks shipped records against the DB rows.

Per **INV-AUDITVERIFY-01**, both are **independent re-implementations** of the
format from this ADR's §2 spec. They must not import the journal package or
`internal/storage`. A differential test (the INV-AUDITVERIFY-02 pattern) builds
real journals with the writer and parses them with the verifier. Journal decoding
gets a fuzz target, added only through its own `scripts/fuzzing/targets.d/` file
(the INV-AUDITVERIFY-15 pattern).

New verdicts are added to `verdictRank` and escalate only, never downgrade
(INV-AUDITVERIFY-05):

- `journal_gap{replica, from, to}`: acknowledged-but-unshipped records from a
  node that is gone. Distinct from tamper, like the retention gap
  (INV-AUDITVERIFY-14).
- `journal_corrupt`
- `journal_forked`
- `journal_regressed`
- `replica_chain_mismatch`: the DB-side reconstruction fails, which is tamper.

### 6. HA and multi-replica (ADR-039)

- **Replica identity.** Today there is none (no replica or node id anywhere).
  `replica_id` is minted once per journal directory and stored in `JOURNAL-ID`.
  It is not the hostname, because pods reschedule. The identity follows the
  volume.
- **Exclusivity.** `flock` on `<dir>/LOCK` prevents two processes on one host
  from sharing a directory. Across hosts, two nodes can mount the same
  RWX/NFS volume or restore the same snapshot. Against that, startup registers
  in `audit_journal_replicas`. If the row is `active` with
  `last_heartbeat_at` newer than `3 × heartbeat`, and the local head does not
  match the DB's `shipped_hash` lineage, startup refuses.
- **Fork detection.** A cloned volume produces two diverging chains under one
  `replica_id`. The ship transaction's continuity check (`seq = shipped_seq+1`
  **and** `prev_record_hash = shipped_hash`) rejects the second chain's first
  batch. That replica's row is marked `forked`, both nodes fail closed for
  gating reads, and `verify` reports `journal_forked`. NFS for the journal
  directory is not supported (`flock` and `fdatasync` semantics vary). The docs
  say so, and startup warns on `nfs`/`cifs` `statfs` types.
- **How chains merge and anchor.** They do not merge into a new structure.
  Each per-replica chain is a sub-sequence of the single global ADR-029 DB
  chain, identified by `(journal_replica_id, journal_seq)`. The DB chain is the
  total order. The replica chains prove that each node's contribution is
  complete and unmodified, and external anchoring covers both (§5). A merkle or
  cross-replica "chain of chains" was considered and rejected. It adds a second
  global serialization point to solve a problem the existing DB chain already
  solves.
- **A replica dies with unshipped records.**
  - *Volume survives, node comes back:* recovery runs and the shipper resumes
    from `shipped_seq+1`. Nothing is lost.
  - *Volume survives, node does not come back:* `keyorix-server admin
    audit-journal drain --dir <path>`, run from any host that has the volume and
    DB credentials, takes the replica's row to `draining`. It verifies the
    journal end to end (chain, seals with the KEK if available) and ships
    exactly as the live shipper would, under the same lock and continuity
    check. It then marks the row `retired`. It is air-gap safe: no network
    beyond the DB.
  - *Volume lost:* records `shipped_seq+1 … durable_seq` are gone. `verify`
    reports `journal_gap` with the exact range and replica. `admin audit-journal
    retire --replica <id> --acknowledge-gap` records an audit event naming the
    operator and the range, marks the row `retired`, and changes the verdict
    from "unexplained gap" to "acknowledged gap". The verdict stays visible and
    is never cleared. The maximum size of this gap is bounded by backpressure
    (§3).
- **Scheduler interaction.** The shipper is **not** a `WithSchedulerLock`
  singleton. Every node ships its own journal concurrently, and the shippers
  serialize only on KEYAUDIT per batch. Checkpoints stay HA-gated as today.
- **Contention.** N shippers contend for KEYAUDIT with batched multi-row
  inserts. A batch holds the lock for about one multi-row INSERT plus one
  commit, instead of today's one commit per flusher batch per node. Total
  KEYAUDIT acquisitions per second drop.

### 7. Retention purge must become id-prefix-based (precondition, pre-existing hazard)

`DeleteAuditLogsBefore` (`internal/storage/store/local_audit.go:350`) deletes
`WHERE event_time < cutoff`. It then anchors the **earliest surviving row by
id**. That is correct only if `event_time` is monotonic in `id`. If a row with
a higher id has an older `event_time` than a row below it, and the cutoff falls
between them, the purge deletes a **mid-chain** row. The re-anchor covers only
the new head of the prefix, so the chain then breaks at the hole and `verify`
reports tampering. The purge also does not take KEYAUDIT.

- **This is latent today.** Concurrent writers produce ms-scale `event_time`
  inversions, and in HA there are also clock-skew-scale inversions between
  replicas. It bites only if an inversion straddles a purge cutoff.
- **Journal mode makes it routine.** Rows shipped late by one node land after
  newer rows from other nodes. Inversions become up to `max_unshipped_age`, or
  hours for an offline drain.

**Required change (lands before journal mode can be enabled, independently
useful now):** purge deletes the longest **id-prefix** whose rows are all older
than the cutoff, `id < (SELECT MIN(id) FROM audit_events WHERE event_time >=
cutoff)`, under KEYAUDIT. It is guarded by a test that interleaves inverted
`event_time`s across the cutoff and asserts that the chain verifies after the
purge. This should be filed as its own issue and PR. It is called out here
because this design turns it from a latent bug into a certain one.

### 8. Disk full and I/O errors: fail closed

- `ENOSPC`/`EIO`/`EDQUOT` on `pwrite` or `fdatasync` poisons the writer (§3).
  The batch fails (no disclosure), gating reads return 503 and readiness goes
  not-ready.
- **Headroom reserve:** the writer refuses *new* segment allocation, and so
  fails gating appends, when free space on the journal filesystem drops below
  `audit.journal.min_free_bytes` (default 1 GiB, or 2× segment size if that is
  larger). It refuses before `ENOSPC` can occur mid-record. Because segments are
  preallocated, a record never fails half-written for lack of space inside an
  allocated segment.
- **Metrics:** `keyorix_audit_journal_free_bytes`,
  `keyorix_audit_journal_unshipped_records`,
  `keyorix_audit_journal_unshipped_age_seconds`,
  `keyorix_audit_journal_fsync_seconds` (histogram),
  `keyorix_audit_journal_batch_size`. Alerting recommendations go in the
  operator docs.
- **Rejected alternative: fall back to the synchronous DB path when the journal
  fails.** That path is not lossy, but the node would silently switch
  durability domains mid-stream. A record could then reach the DB ahead of
  earlier journal records from the same node that are still unshipped, which
  breaks per-node seq order. A disk that fails `fsync` is also not one to keep
  serving from. Failing closed and draining the node is simpler and easy to
  observe.

### 9. Air-gapped, backup and restore, file registries

- **Air-gapped:** fully local, no new network dependency. The offline drain
  (§6) and offline verify (§5) need only the volume and DB access.
- **Backup (`server/admin/backup.go`):** the journal directory is **not** an
  archive member, the same rule the witness file follows (INV-AUDITVERIFY-11).
  The new tables and columns *are* captured, because backup dumps every
  `storage.AllModels()` table and `audit_journal_replicas` joins `AllModels()`
  (guarded by `TestAllModels_MatchesLiveMigratedTables`). Before taking a
  snapshot, `admin backup` drains the **local** node's journal, so a
  single-node backup contains every acknowledged record. On HA, the archive
  contains what was shipped at snapshot time, and the manifest records each
  replica's `(shipped_seq, durable_seq)` so the in-flight set at backup time is
  explicit.
- **Restore (`server/admin/restore.go`):** restore rolls the DB back and leaves
  the journal in place, so the journal is ahead of the restored
  `shipped_seq`. Two cases:
  - *The segments covering the difference are still retained:* the shipper
    re-ships them, which restores audit records the rollback would otherwise
    have lost. This is the correct behaviour, since they are real, disclosed
    events.
  - *They have been deleted:* the continuity check fails (`first available seq >
    shipped_seq+1`). The shipper refuses to ship across the hole and `verify`
    reports `journal_gap`. Restore's existing rollback gate
    (`checkRollbackProtection`, witness high-water mark, `--allow-rollback`
    audited) already requires an explicit operator decision for a rollback.
    `--allow-rollback` therefore also authorizes `admin audit-journal retire
    --acknowledge-gap` for affected replicas. That way the acknowledged gap and
    the acknowledged rollback are one recorded decision, not two.
- **`internal/keyfiles.Registry`:** the journal is **not** added. Registry
  enumerates *key material*, and Registry drives backup/restore
  (`backup.go:351`, `restore.go:484`). Adding the journal there would make
  restore overwrite it, which is exactly the case INV-AUDITVERIFY-11 forbids for
  the witness file.
- **Permission checking:** the journal directory (0700) and its files (0600) are
  checked at **every** startup, **unconditionally**. This is a new file type
  with no legacy installs to break, so it does not inherit
  `security.enable_file_permission_check`'s off-by-default. A mismatch refuses
  start, and there is no `allow_unsafe` downgrade for it. Repair is an explicit
  operator action (`securefiles.FixFilePerms` behind an admin command), never
  automatic at boot. `validateFilePermissions` and `enforceKeyFilePermissions` both
  keep their own hand lists today. The journal spec should be added through one
  shared non-key-file enumeration with an exhaustiveness guard (the
  `registry_exhaustiveness_test.go` pattern), not as a fifth hand list.
- **Encryption at rest:** journal records hold the same metadata as
  `audit_events` (ids, IPs, descriptions, diffs, and never values).
  `audit_events` is not application-encrypted today, so neither is the journal.
  Disk encryption is operator-owned, as it is for the DB.

### 10. SQLite

Journal mode is supported on SQLite. The case for it is weaker, since a single
node already has the DB on local disk with one fsync per commit. The gain there
is pipelining: about 1 fsync per *arrival burst* instead of 1 per flusher batch
plus SQLite's write lock. The ship transaction takes the single SQLite write
lock with large batches, so it amortizes. The PERF measurement covers SQLite
separately and may conclude that journal mode should be Postgres-only. That is
an explicit outcome the plan allows.

## Expected performance, from first principles

Notation: `F` is the device's durable-flush latency (pve01: **F ≈ 9.3 ms**
measured). `S` is the non-audit service time of one read (decrypt, authz, DB
fetch, HTTP).

**c=1.** No batch can form, so each read waits one `fdatasync`: `latency ≈ S +
F`. **Throughput ≤ 1 / (S + F) ≤ ~107 reads/s on pve01. That is the same
ceiling as today**, because today's c=1 cost is also about one flush per read.
The journal removes only the advisory-lock, head-SELECT and INSERT round trips,
plus the DB's own WAL overhead, which is at most a few ms. **So on pve01's disk
the c=1 target ("within 2x of Vault-audit-on") is not achievable by this design,
or by any design that keeps fsync-before-disclosure.**

Vault-audit-on at c=1 is about 10× Keyorix's ~100/s, roughly 1,000/s, or about
1 ms per read. That is only possible because, to our reading, Vault does not
flush the device per entry. Within 2× would require about 2 ms per read, which
is below one 9.3 ms flush. The c=1 target becomes reachable only when `F` is
small: a device with power-loss-protected write cache (enterprise SSD/NVMe with
PLP, or a battery-backed RAID controller), where a flush costs roughly 20–200 µs.
Then `latency ≈ S + 0.2 ms`, and the journal's advantage over the DB path
(no round trips) becomes the dominant term. **The only way to hit the c=1 target
on pve01 as measured is to weaken the guarantee to Vault's (write, no fsync).
This ADR rejects that.**

**c=50.** With pipelining, a batch forms of every arrival during the previous
flush. In steady state each fsync covers up to ~50 records:

- Flush ceiling: `50 / F ≈ 5,400 reads/s` on pve01. The fsync is amortized to
  about 0.19 ms per read.
- Encoding plus SHA-256 per record costs a few µs, which is negligible.
- The read path then becomes `S`-bound, not audit-bound.

Today's c=50 path is bounded by the per-batch DB transaction. That is one flush
**plus** about 2 INSERT round trips per item (event and access log) inside the
same lock-held transaction, and it is not pipelined: arrivals during a commit
wait for the next flusher iteration. With ~0.3 ms per INSERT round trip, a
50-item batch costs about 9.3 + 30 ms, a ceiling of ~1,250/s, in the region
PERF-2 measured. The shipper moves those INSERTs off the read path and batches
them as multi-row INSERTs (≫ 1,000 rows/s per KEYAUDIT hold).

**Expected outcome: c=50 within 2× of Vault-audit-on is plausible, provided `S`
itself is within 2×.** PERF-2 showed Vault's audit costs nothing at c=50, so the
6.4× gap at c=50 may be partly non-audit cost. The measurement plan has to
separate the two.

## Measurement plan (PERF kit on pve01)

Run every cell on pve01 with the PERF-2 harness, same Vault version and same
hardware. Each cell is 3 × 60 s runs, reported as median with min and max:

| Variable | Values |
|---|---|
| Keyorix mode | `off` (#2420 flusher, linger 0), `shadow`, `on` |
| Backend | Postgres, SQLite |
| Concurrency | c = 1, 10, 50 |
| Vault | audit off, audit on (file device) |
| Diagnostic only | Keyorix built with a **test-only build tag** that stubs the audit append. It is never a config switch and never shippable. It measures `S`. |

Also record:

1. `F`, measured directly on the journal volume: `fio --fdatasync=1` and a
   standalone Go loop that does `pwrite` + `fdatasync` on a preallocated file.
2. The journal batch-size distribution.
3. Ship lag p50/p99.
4. Whether Vault's file device calls `fsync`, confirmed by `strace -f -e
   trace=fsync,fdatasync` on the Vault process during the c=1 run. The c=1
   reasoning above depends on this.

Durability proofs, repeated in `on` mode (the #2420 kit):

- SIGKILL mid-run at c=1 and c=50 on both backends, then restart. `admin
  verify-audit --force` must be VALID, and *delivered ≤ shipped-for-the-run*
  must hold.
- Repeat with the node's host power-cycled (VM hard reset), not just the
  process.
- Fill the journal volume to ENOSPC mid-run. There must be zero 200-with-value
  responses after the first journal write error, and the readiness probe must
  flip.
- Inject an `fdatasync` failure (a dm-flakey or FUSE fault shim). The writer
  must be poisoned and no batch may be acknowledged.

**Success criteria:**

1. **c=50:** `on` is within 2× of Vault-audit-on throughput on both
   backends, with p99 no worse than `off`.
2. **c=1:** `on` is no worse than `off` (within noise). Within 2× of
   Vault-audit-on is required **only** on a PLP device (`F` < 0.5 ms), measured
   on such a device. On pve01 the reported result is the measured `F` floor and
   the ratio `(S+F)/S`, which explains the gap. "Not met on pve01" is the
   expected result, not a failure.
3. **Durability:** every proof above is green, with zero delivered values whose
   audit record is missing after recovery.
4. **Shadow differential:** in `shadow` mode, over the whole PERF run, every DB
   row written by the authoritative path has a journal record whose field
   values are byte-identical (§11).

If criterion 1 fails because `S` dominates (the diagnostic build is also far
from Vault), this ADR still holds on correctness, but its rationale does not.
The status then moves to **Rejected (rationale not met)** and the work goes to
the non-audit read path.

## Feature flag and migration

`audit.journal.mode`:

- **`off`** (default): today's #2420 path. The journal code is not started. If a
  journal directory with unshipped records exists, startup **refuses**, so
  switching `on` → `off` can never orphan acknowledged records. The operator runs
  `admin audit-journal drain` first.
- **`shadow`** (dark ship): the DB path stays authoritative for the
  disclosure gate. Each append **also** goes through the journal writer and
  group fsync, and both must succeed before returning (`shadow` is the slowest
  mode, and is for measurement and validation). The shipper runs in
  **compare** mode: it does not insert. The authoritative path stamps
  `journal_replica_id`/`journal_seq` on the row it inserts, and the compare
  shipper looks each journal record up by that key and asserts byte-identical
  field values. It also asserts that the DB-side replica-chain reconstruction
  (§5) matches the journal's `record_hash`. Mismatches increment
  `keyorix_audit_journal_shadow_mismatch_total` and are logged. Segments are
  deleted after compare. This is the side-by-side comparison: the same process
  measures both fsync costs (`_fsync_seconds` vs the existing flusher metrics)
  and proves the format round-trips on real traffic.
- **`on`**: the journal is authoritative. §§3–8 apply.

**Schema changes** are additive only, and use the ADR-029/ADR-078 discipline:
`ALTER TABLE … ADD COLUMN` guarded by `columnExists`, never `AutoMigrate` on an
existing table.

- `audit_events`: add `journal_replica_id text NULL`, `journal_seq bigint NULL`,
  `journal_hash text NULL`, plus the unique partial index.
- `secret_access_logs`: add `journal_replica_id`, `journal_seq`.
- Create the `audit_journal_replicas` table.

Old binaries ignore the new columns, so no `currentSchemaEpoch` bump should be
needed. That must be re-checked against ADR-101 when it is implemented, not
assumed.

**Rollout order:**

1. Land the id-prefix purge fix (§7).
2. Land the schema, the independent `auditverify` journal reader and the fuzz
   target.
3. Land the writer, recovery and shipper behind `mode: off`.
4. Run `shadow` in the PERF kit, then on a staging HA deployment for ≥ 1 week.
5. Turn on `on` per environment.

**Rollback:** drain, then switch to `off`. The startup refusal above enforces
the order.

## Invariants

Everything the touched packages' `INVARIANTS.md` files list for the audit chain
is preserved as follows. New invariants are added to those files **when the
implementation lands**, not by this ADR.

| Existing invariant | How it holds |
|---|---|
| INV-CORE-22 (`emitAudit` is the choke point) | The journal is below `Storage`, so core does not change. |
| INV-CORE-24/25 (retention purge keeps the chain verifiable; legal hold blocks purge) | Holds **only after** §7's id-prefix fix, which is a hard precondition. Legal hold is unchanged. |
| INV-CORE-26/37 (audit after commit; no SUCCESS audit before its write) | Ordering is relative to the caller's write, which is unchanged. |
| INV-STORE-04/05/06 (advisory-lock keying, connection reuse, cross-replica serialization) | Same KEYAUDIT key, same `pg_advisory_xact_lock`. The shipper adds acquisitions, not a new primitive. |
| INV-STORE-20 (UTC event times) | The journal stores UTC UnixMicro, and the shipper inserts `time.UnixMicro(...).UTC()`. |
| INV-STORAGE-28 (advisory locks have no filesystem dependency) | Unchanged. The journal's filesystem dependency is new and separate (proposed INV-STORAGE-36/37). |
| INV-STORAGE-29 (fresh SQLite file 0600) | Unchanged. The journal gets its own 0600/0700 rule (proposed INV-STORAGE-37). |
| INV-AUDITVERIFY-01 (no core/storage imports) | The journal reader is an independent re-implementation from §2. |
| INV-AUDITVERIFY-02/03 (canonical byte agreement) | The canonical forms are unchanged. A new differential pair is added for the journal record. |
| INV-AUDITVERIFY-05 (escalate only) | The new verdicts slot into `verdictRank`. |
| INV-AUDITVERIFY-06/07/08 (byte tamper, tail truncation, forged checkpoint detected) | DB-side unchanged. Journal analogues are added (§5). |
| INV-AUDITVERIFY-10/11 (witness monotone; witness not a backup member or in Registry) | Unchanged. The journal follows the same not-a-member, not-in-Registry rule. |
| INV-AUDITVERIFY-12 (key domain separation) | `K_journal` uses its own HKDF info string. |
| INV-AUDITVERIFY-14 (retention gap is a distinct status) | `journal_gap` is likewise distinct from tamper. |
| INV-AUDITVERIFY-15 (decoder never panics or hangs) | A new fuzz target for journal decoding. |

**Proposed new invariants** (each needs its guard before `mode: on` is allowed
outside `shadow`):

- **INV-STORAGE-36:** a `LogAuditEvent*` nil return means the record is durable
  (DB commit or journal `fdatasync`). After any write or sync error the journal
  writer acknowledges nothing until restart. *Guard:* a fault-injection test that
  fails `fdatasync` and asserts zero nil completions, plus a handler-level test
  asserting 503 and no `"value"` key.
- **INV-STORAGE-37:** the journal directory is 0700, its files are 0600, it is
  created via `securefiles` beneath-opens, and it is checked unconditionally at
  startup. *Guard:* a umask 022/000 test (the INV-STORAGE-29 pattern) and a
  startup-refusal test.
- **INV-STORE-21:** the shipper ships per-replica records in contiguous seq
  order, with progress and data in one transaction, never skips a record, and
  never bisects. *Guard:* a crash-at-every-statement test (the
  `FuzzStorageFaultOperations` pattern, through a new op registration and **not**
  by editing the serialized hotspot files) and a pg-gated two-shipper
  continuity/fork test.
- **INV-STORE-22:** audit retention purge deletes only an id-prefix (§7).
  *Guard:* the interleaved-inversion purge test.
- **INV-AUDITVERIFY-16:** DB-side replica-chain reconstruction detects edits to
  `journal_*`, `machine_identity_id` and joined access-log fields. *Guard:* an
  exhaustive byte-tamper test (the INV-AUDITVERIFY-06 pattern).

## Alternatives considered

1. **Status quo (#2420 flusher, linger 0).** It is correct and fail-closed. It
   leaves c=50 bounded by per-item INSERT round trips inside a lock-held,
   non-pipelined transaction. **Kept as the default (`off`)** and as the
   comparison baseline. Rejected as the end state only if the measurement plan's
   c=50 criterion is met by `on`.
2. **Tune the flusher's linger.** #2420 measured this already: on the benchmark
   VM, any nonzero linger cost about 6 ms at c=1 (timer granularity) and made
   Postgres c=10 *worse* (705 → 258–525 rps), for roughly 2× at c=50. It does
   not change what the flush is (one DB transaction with per-row round trips).
   It only changes how many items wait for one. **Rejected** as the main lever.
   The knob stays available (`audit_flusher_linger_window`).
3. **SQLite WAL-only audit DB** (a separate SQLite file for audit, even on
   Postgres deployments). A commit is still a WAL fsync plus B-tree and index
   maintenance plus the single-writer lock. It is a journal with more overhead
   and without a seq/replica identity. In HA it would be a per-node DB that
   needs the same shipper this ADR designs anyway. **Rejected**: it adds the
   shipper's complexity without the append-only file's simplicity or
   verifiability (offline verification of a flat TLV file is far easier to
   re-implement independently, per INV-AUDITVERIFY-01, than SQLite page
   parsing).
4. **Unlogged Postgres table plus WAL shipping.** `UNLOGGED` tables are
   **truncated on crash recovery** and not replicated, which directly
   contradicts "durable before disclosure". Shipping "its WAL" is not possible,
   because unlogged tables write no WAL by definition. Lowering
   `synchronous_commit` per transaction (`SET LOCAL synchronous_commit=off`)
   makes a commit return before the WAL flush, which is the Vault-style
   weakening by another name. **Rejected** on durability.
5. **Weaken to write-without-fsync (Vault's guarantee).** This would hit the c=1
   target on pve01. It loses acknowledged audit records on OS crash or power
   loss, after their values were disclosed. **Rejected**: the requirement is
   non-negotiable, and #2420 exists precisely to close that class.
6. **Merge the journal tail into the audit API.** Rejected (§4): the answer
   would depend on which replica served it, and the records would have no
   `entry_hash`.
7. **Cross-replica "chain of chains" (merkle or periodic cross-anchor).**
   Rejected (§6): the DB chain already gives the total order. Replica chains plus
   off-box recording of `(replica, shipped_seq, shipped_hash)` give per-node
   completeness without a second global serialization point.

## Consequences

- **Positive:** the c=50 audit cost moves from per-item DB round trips under a
  lock to one amortized local flush. Ship batching cuts KEYAUDIT acquisitions.
  Replica chains make `machine_identity_id` and access-log rows tamper-evident
  for journal-mode rows, which today's chain does not do. Node identity becomes
  explicit, which ADR-039 lacked.
- **Negative:**
  - A new durability domain with real operational surface: a persistent volume
    per node, fork and restore semantics, a drain tool, disk alerts.
  - A bounded, detected, but real loss window on node-volume loss (§3).
  - Audit API visibility lags by up to `max_unshipped_age`.
  - Anomaly detection lags by the same bound.
- **Neutral or honest:** on hardware like pve01's disk, c=1 does not improve
  meaningfully. The ADR says so up front instead of letting a c=50 result be
  read as a c=1 claim.

## Ratification preconditions

Before this moves to **Accepted**:

1. #2420 is merged (the baseline guarantee exists on `main`).
2. The id-prefix purge fix (§7) is merged, with its guard.
3. The measurement plan has run on pve01 with success criteria 1, 3 and 4 met,
   and criterion 2 reported (met on a PLP device, or the pve01 floor explained).
4. The Vault no-fsync reading is confirmed by `strace`. If Vault does fsync per
   entry, the c=1 analysis in "Expected performance" must be redone before
   ratifying, because the gap would then have to be explained by something else.
