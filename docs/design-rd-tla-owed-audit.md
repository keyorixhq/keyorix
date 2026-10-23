# Design note: a TLA+ model of the owed-audit design

Status: R&D prototype (RD-TLA-OWED-1), 2026-10-23. Docs only, not run by CI.
Model, configurations and how to run them: `docs/formal/owed-audit/README.md`.
Demo: `docs/demo/tla-owed-audit.md`.

## Context

ADR-112 makes two promises that pull against each other while the audit log is
refusing writes:

- **A revocation is never blocked by the audit log** (Andrei 2026-10-14;
  INV-CORE-revocation-audit-owed, INV-CORE-plain-suspend-audit-owed).
- **Nothing security-relevant happens without a record.** A grant commits
  with its audit row or not at all (INV-CORE-security-mutation-audit-same-tx).
  A revocation commits with a `pending_audit_events` record of the row it owes
  (`audit_owed.go`). A request that both narrows and widens is split, narrowing
  first (INV-CORE-mixed-request-split). Break-glass may commit during an outage
  only together with owed records (ADR-112 Amendment 6).

Today these promises rest on code review, the `internal/core` matrices and
the faultops owed-audit oracle. All of them check concrete interleavings and
fault positions: one injected fault at a time in the fuzzer, hand-picked
double faults in the core tests. REVIEW-3482 F1 (a mixed request failing
closed as a whole, so an outage blocked its revocation) was found by review,
not by a tool.

## Decision

Keep a small TLA+ model of the protocol in `docs/formal/owed-audit/`. It
covers revoke, widen, the mixed split, break-glass (normal and degraded), the
request's own settle step, the backfill on several replicas, an audit-log
outage, a pending-table outage and a process crash. TLC checks it
exhaustively within stated bounds against these properties:

| Property | Kind | Brief item |
|---|---|---|
| `RevocationNeverBlocked`: every narrowing request ends in force even if the audit log never comes back | liveness | revocation never blocked |
| `NoUnrecordedEffect`: every row an effect owes is in the chain, in the owed ledger, or held by the live request about to write it | invariant | no unrecorded effect |
| `ChainValid` (linked, exactly once, no phantom) and `CompleteAfterBackfill` | invariant | chain valid after backfill |
| `WideningFailClosed`: a grant's rows are in the chain; a degraded break-glass's rows are in the chain or the ledger, never only in memory | invariant | widening fail closed |
| `OwedOrderPreserved`, `NarrowingFirst`, `BreakGlassSettlementSound`, `BackfillConverges` | invariant / liveness | Amendment 6 order, split order, verifier verdict, drain |

Four seeded bugs, each in its own configuration, show that the properties
are not vacuous: TLC must find each one. A fifth, `late_after_wait`, is the
owed-audit code before RD-TLA-OWED-FIX-1, kept so the silent-loss trace
stays reproducible. The verdict table is in the README.
`run-tlc.sh` reruns every configuration and fails if any verdict changes.

## New vs state of the art

- Formal models of audit logging usually treat the log as an append-only
  sink that is always available, or they verify the log's tamper evidence
  (hash chains, Merkle trees, as in Crosby & Wallach's tamper-evident
  logging). They do not model the interaction this design needs: an
  authorization effect, a durable "owed" record in the same transaction, a
  later settle or backfill under a failing log, and an asymmetric policy
  (revocations never wait, grants fail closed). We have not found a published
  model of that combination. This is a search claim, not a proof.
- Vault and OpenBao take the opposite position: a request fails when no
  audit device can record it, and that includes a token revocation. Their
  documentation describes this blocking behaviour; we know of no formal
  model of it. The model here makes the Keyorix asymmetry precise. It also
  shows by seeded bug 2 why the obvious shortcut fails: a single direction
  per request makes a mixed request block its own revocation.
- Industrial TLA+ use (AWS, Azure Cosmos DB, MongoDB replication) targets
  replication and consistency protocols. Applying it to an audit-durability
  policy of a secrets manager, with the policy's exceptions modelled as
  first-class actions, is the new part. The modelling technique is standard.

## Technical risks

- **Model and code drift.** Nothing ties `OwedAudit.tla` to `audit_owed.go`.
  A change to the settle order, the claim, or the collect-only fallback can
  make the model wrong without any failure. Mitigation: the README maps every
  action to a function, and a change to those functions should update the
  model. No guard enforces this. A guard (for example a test that fails when
  `audit_owed.go` changes without `OwedAudit.tla`) is possible but is not
  built here.
- **Bounds.** TLC proves the properties only within the configured bounds:
  at most 4 requests, 2 replicas, 3 availability flips and 1 crash. The bugs
  this design is exposed to need 1 or 2 faults, and the counterexamples TLC
  found are 3 to 9 states long. This is evidence, not a proof for every
  population. TLAPS proofs or Apalache inductive invariants would remove the
  bound. They are not done.
- **Abstraction gaps.** The model does not cover these (each one is listed
  in the README):
  - Amendment 3's `standard` tail loss;
  - the hash function;
  - clocks, TTLs and original event times;
  - several replicas' auth caches;
  - payload decode failures;
  - an append that commits but reports an error (the documented duplicate);
  - PostgreSQL abort semantics (REVIEW-3482 F2/F4).

  A property that depends on any of these is not established by the model.
- **Known gaps confirmed, not closed.** Two documented gaps show up as
  violations, and the model makes them precise without fixing them:
  - With a second, independent fault (the pending table refusing inserts),
    `NoUnrecordedEffect` fails. This is the documented "NOT queued for
    backfill" gap, logged loudly.
  - With that fault plus a process crash at the wrong moment, the row is
    lost **silently** (`NoSilentLoss` fails). The collect-only rows live only
    in memory, so no log line is written. INV-CORE-revocation-audit-owed said
    that "a crash between the commit and the append loses nothing". That was
    true only on the normal path, not on the collect-only fallback. Narrowed in
    code by RD-TLA-OWED-FIX-1 (see Consequences).
- **Chain order is not effect order.** An owed row is appended after rows of
  later effects (`explore_effect_order.cfg`). For a mixed request across an
  outage, the remainder's row can precede the narrowing's row in the chain. A
  non-break-glass backfilled row then carries the backfill time as its
  `event_time`, with the real time only in its description. An auditor who
  reconstructs a timeline from chain order or `event_time` alone gets it
  wrong. This is by design, but it is not stated in the ADR today.

## Consequences

- The four properties of the brief hold in every configuration that has no
  seeded bug, with or without a crash, as long as the pending table is
  available.
- The silent-loss case is new information for the owed-audit invariant. It
  cannot be closed completely: by definition the record could not be
  written with the effect, so some window remains between the commit and
  any later record. It can be narrowed, for example by queueing the late
  record right after the commit, before the bounded append wait, rather
  than after the append fails. Decided (ask `rd-tla-owed-silent-loss`, a)
  and done in RD-TLA-OWED-FIX-1: the late record is written right after the
  commit and the rows are named in a `SECURITY:` line before it. The model
  keeps the old code as seeded bug `late_after_wait`; `pendingfault_fixed.cfg`
  checks the fix (`LossOnlyWhereUnrecordable`). The invariant's crash
  sentence now names the paths that remain: a crash before the late record
  commits, and the late record refused too followed by a crash before the
  direct append. Both are loud.
- A future change to the owed-audit protocol can be checked in minutes with
  `run-tlc.sh` before it is implemented.
