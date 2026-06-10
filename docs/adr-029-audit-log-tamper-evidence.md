# ADR-029: Audit-log tamper-evidence (hash-chained audit events)

**Status:** Accepted
**Date:** 2026-06-10
**Context:** NIS2 / DORA audit-log provisions; the honest "tamper resistance"
gap flagged in `docs/compliance/AUDIT-LOG-PROVISIONS.md` (checklist row 11).

## Context

Keyorix audit events are stored in the operator's PostgreSQL with no purge and
no cap (retention is unbounded — see the audit-retention coverage API). The
remaining integrity gap is **tamper-evidence**: nothing detects after-the-fact
modification, deletion, or reordering of audit rows by anyone with database
access. Auditors (DORA Art. 9-style record integrity) want evidence that the
trail has not been altered, not just that it exists.

Full WORM (write-once-read-many) immutability needs infrastructure outside the
application's control (append-only storage, an external notary/timestamp
authority, or a managed immutable ledger). What the application *can* provide,
self-contained, is **tamper-evidence**: a cryptographic hash chain over the
audit rows so that any modification/deletion/insertion is detectable.

## Decision

Maintain a SHA-256 **hash chain** over `audit_events`. Each event stores:

- `prev_hash` — the `entry_hash` of the immediately preceding chained event
  (or a fixed genesis constant for the first chained event).
- `entry_hash` — `SHA256( canonical(event fields) ‖ prev_hash )`.

Because each entry's hash binds the previous entry's hash, altering any field of
any row, deleting a row, inserting a row, or reordering rows breaks the chain at
that point and is detectable by re-walking it.

### Canonical encoding

`entry_hash` is computed over a **fixed-order, null-separated** encoding of the
semantically meaningful fields: `prev_hash`, `event_type`, `user_id`,
`secret_node_id`, `project_id`, `ip_address`, `description`, `success`,
`event_time`, `diff`, `impersonated_by`, `acting_as`, `impersonation`,
`actor_type`. The DB-assigned `id` is **deliberately excluded** — it is not
known before insert, and chain linkage already pins each row's position.

`event_time` is encoded as **Unix microseconds** (`UnixMicro`), and the stored
`event_time` is truncated to microseconds before both hashing and insert. This
is required for correctness: PostgreSQL `timestamptz` has microsecond precision,
so a nanosecond-precision `time.Now()` would not round-trip and verification
would fail for every row. Truncating up front makes the stored value exactly
equal to the hashed value on both Postgres and SQLite.

### Serialization (correctness under concurrent writers)

Audit events are emitted from detached goroutines, so appends are concurrent. A
hash chain requires the read-previous-hash + insert to be atomic. The write is
therefore serialized:

1. A process-level mutex on the storage handle (covers the common single-writer
   self-host topology and SQLite, which serializes writes anyway).
2. Inside a DB transaction, a PostgreSQL **transaction-scoped advisory lock**
   (`pg_advisory_xact_lock`) guards the critical section across processes for
   multi-instance Postgres deployments (no-op on SQLite).

The transaction reads the current chain head (`entry_hash` of the highest-`id`
row), computes the new `entry_hash`, and inserts — all under the lock.

### Verification

`VerifyAuditChain` walks events by ascending `id` in bounded batches and, for
each chained row, (a) checks `prev_hash` equals the running previous
`entry_hash` (genesis for the first), and (b) recomputes `entry_hash` from the
row's stored fields and checks it matches. The first divergence is reported with
the offending `id` and reason. Exposed as `GET /api/v1/audit/verify`.

### Legacy rows

Events written before this ADR have empty `prev_hash`/`entry_hash`. Verification
treats a leading run of empty-hash rows as an **unchained legacy prefix** (counted,
not failed); the chain begins at the first row written after the columns exist.
New columns are added via additive `ALTER TABLE` guarded by `columnExists`
(never via a full `AutoMigrate` on an existing table — avoids the pgx
double-migration hazard).

## Consequences

- **Detectable**, not **prevented**: an attacker with DB write access can still
  modify rows, but cannot do so *undetectably* without recomputing the entire
  forward chain — and cannot at all if a verified `entry_hash` has been exported
  off-box (SIEM push already forwards every event). Re-anchoring the head to an
  external notary/SIEM is a future enhancement.
- Audit writes now take a lock + transaction. Audit emission is already
  asynchronous/best-effort and off the request hot path, so the added latency is
  not user-visible.
- WORM/immutability (append-only physical storage) remains out of scope and
  operator-owned; this ADR delivers tamper-*evidence*, moving compliance
  checklist row 11 from "⚠️ Roadmap" to "✅ hash-chained (verification API);
  physical immutability operator-owned".
