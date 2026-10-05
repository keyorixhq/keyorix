# Threat Model: Audit Chain

> Part of [`docs/security/threat-models/`](README.md). Derived from
> [ADR-029](../../adr-029-audit-log-tamper-evidence.md) and
> [`../architecture.md`](../architecture.md) §3 — those documents are the
> detailed design; this is the threat-modeling view of the same
> mechanism.

## 1. System context

Every security-relevant action writes an `audit_events` row, hash-chained
so that modification, deletion, insertion, or reordering of a row still
present in the table is detectable by re-walking the chain. Because a
*shorter, self-consistent* chain (tail-truncation or a genesis re-seed)
still re-walks as valid, three independent, composable mechanisms close
that specific gap — this is the one place in the whole system where the
threat model has to reason about an attacker with direct database
write access as a first-class case, not an edge case.

```mermaid
flowchart TB
    EVENT[Security-relevant action\n(any handler/service)]
    WRITE["Serialized write:\nprocess mutex +\nPostgres pg_advisory_xact_lock"]
    CHAIN[("audit_events\nprev_hash, entry_hash\n(SHA-256, TLV-encoded fields)")]
    CKPT[("audit_checkpoints\nHMAC-SHA256, keyed by\nKEK-derived key (in-memory only)")]
    SCHED[Checkpoint scheduler\n(enabled whenever a signing\nkey is available)]
    VERIFY["VerifyAuditChain /\nGET /api/v1/audit/verify"]
    OFFLINE["keyorix-server admin verify-audit\n(internal/auditverify — independently\nimplemented, not the writer's own code)"]
    ANCHOR[Off-box anchor /\nRFC 3161 TSA\n(--anchor / --tsa-roots)]

    EVENT --> WRITE --> CHAIN
    SCHED -->|periodic| CKPT
    CKPT -. authenticates .- CHAIN
    CHAIN --> VERIFY
    CKPT --> VERIFY
    CHAIN --> OFFLINE
    CKPT --> OFFLINE
    OFFLINE -. ground truth held\noutside this host .-> ANCHOR
```

## 2. Trust boundaries

| Actor | What they can do | What they can't do |
|---|---|---|
| Ordinary authenticated caller | Nothing to the chain directly — only generates events through normal operations | Write, modify, or delete `audit_events`/`audit_checkpoints` |
| DB-level actor (root on the DB, or an admin with DB access) | Modify/delete/insert/reorder rows (detectable); delete or overwrite the latest checkpoint row (forces `verify` to fail closed until the next scheduler re-baseline) | **Forge** a checkpoint that makes a truncated chain verify as valid — the HMAC key is HKDF-derived from the KEK and held only in server process memory, never in the database |
| Host root (file-KEK install) | Everything a DB-level actor can, plus derive the checkpoint key itself (it comes from the KEK, which host root already has) | Nothing beyond what root already implies system-wide — see `../threat-model.md` §5.1 |
| External auditor with exported checkpoint data | Independently verify the chain was not truncated after the export point, without trusting the running server | Verify anything about events *after* their last anchor point without a fresher anchor |

## 3. Threat table

| ID | STRIDE | Description | Mitigation | Evidence link | Residual risk / GAP |
|---|---|---|---|---|---|
| AUDIT-1 | Tampering | A present audit row is modified, deleted, inserted, or reordered. | Detected by re-walking the hash chain — each entry's `entry_hash` covers a fixed-order, length-prefixed encoding of the row's fields plus the previous entry's hash. | ADR-029 | None — this is exactly what the mechanism is built to catch. |
| AUDIT-2 | Tampering | Tail-truncation or a genesis re-seed produces a *shorter, self-consistent* chain that a bare re-walk cannot distinguish from a genuinely short, untampered chain. | Three composable mechanisms: (1) signed in-DB checkpoints, HMAC-keyed from the KEK, refusing a checkpoint over a shorter chain than an authenticated prior one; (2) an off-box anchor (`--anchor`); (3) a third-party RFC 3161 timestamp authority (`--tsa-roots`), needing no shared secret and no trust in this host at all. | ADR-029 §Consequences; `#502` (KEK-vs-DEK derivation fix) | None for the closed case. See §4 for the DB-level-actor residual that remains. |
| AUDIT-3 | Repudiation | An actor denies performing a security-relevant action. | Every such action is audited with actor identity, `actor_type`, and outcome, including impersonation attribution. | [`../../compliance/AUDIT-LOG-PROVISIONS.md`](../../compliance/AUDIT-LOG-PROVISIONS.md) | Retention is bounded only by the operator's own PostgreSQL retention policy — Keyorix imposes no cap. Documented operator responsibility, not a gap. |
| AUDIT-4 | Information disclosure | The audit trail itself becomes a secondary leak channel for secret values. | Secret-update audit diffs carry only a `{"value":{"changed":true}}` marker, never the before/after value. Audit-before-disclosure ensures a secret-value read's audit write is confirmed durable *before* the value is released, so a failed audit write can't silently decouple from a successful disclosure. | `../../compliance/AUDIT-LOG-PROVISIONS.md` §3; [`../SECURE-CODING.md`](../SECURE-CODING.md) §4 | None identified. |
| AUDIT-5 | Denial of service / tampering (via race) | `WriteAuditCheckpoint` reachable from three unsynchronized triggers (scheduler, HTTP, gRPC) landing on different HA replicas could commit a checkpoint out of chain-length order, silently missing coverage of events in the interleaving window — even with a fully intact, validly-signed chain. | The whole sequence now runs under `storage.WithAuditCheckpointLock`. | `#300` | **Closed.** |

## 4. Residual risks, stated honestly

- **A DB-level actor who can also write `audit_checkpoints` can
  neutralize on-box enforcement** (delete/overwrite the latest
  checkpoint row), forcing `verify` to fail closed until the next
  scheduler re-baseline — within that window a truncation could be
  re-blessed. What such an actor can never do is forge a checkpoint that
  makes a truncated chain verify as valid. Detection in that scenario
  reverts to an off-box external anchor (ADR-029 "Residual (honest
  scope)").
- **No full WORM immutability.** This is tamper-*evidence*, not
  tamper-*prevention* — stated as a deliberate design choice in ADR-029's
  own Context section: full write-once-read-many immutability needs
  infrastructure outside the application's control (append-only storage,
  an external notary, a managed immutable ledger), which is exactly what
  the off-box anchor and RFC 3161 TSA options above are for when an
  operator wants that stronger guarantee.
