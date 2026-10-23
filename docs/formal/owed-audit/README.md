# OwedAudit: a TLA+ model of the owed-audit design

A model of how a security change and its audit row commit when the audit
log may be refusing writes. TLC checks it exhaustively within bounds.
Design note (why, state of the art, risks): `docs/design-rd-tla-owed-audit.md`.
Demo: `docs/demo/tla-owed-audit.md`. R&D prototype; not run by CI.

| File | What |
|---|---|
| `OwedAudit.tla` | the specification: actions, invariants, liveness properties |
| `MCOwedAudit.tla` | the request populations used by the configurations |
| `*.cfg` | TLC configurations (table below) |
| `run-tlc.sh` | fetches the pinned TLA+ tools and runs one or every configuration |

## How to run

Needs Java 11+ (tested with OpenJDK 27) and, on first use, network access to
`github.com` / `release-assets.githubusercontent.com`.

```
docs/formal/owed-audit/run-tlc.sh             # every configuration; checks each verdict
docs/formal/owed-audit/run-tlc.sh small.cfg   # one configuration, full TLC output
```

The script downloads `tla2tools.jar` v1.7.4 (TLC 2.19) into `.scratch/tlc/`
and checks its SHA-256
(`936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`).
`TLA2TOOLS_JAR=/path/to/tla2tools.jar` uses a local copy instead, and
`JAVA=/path/to/java` picks the runtime. To run TLC by hand:

```
cd docs/formal/owed-audit
java -Xmx3g -cp /path/to/tla2tools.jar tlc2.TLC -workers auto -config small.cfg MCOwedAudit.tla
```

The heap is capped at 3 GB. The largest configuration fits in it.

## Configurations and verdicts

TLC 2.19, breadth-first, complete state space. The state counts are
deterministic. Runtimes depend on the machine and are not recorded here.

| Configuration | Population (`Kind`) | Replicas | Flips | Crashes | Pending fault | Expected verdict | Distinct states |
|---|---|---|---|---|---|---|---|
| `small.cfg` | revoke, widen, breakglass | 2 | 2 | 1 | no | all invariants and both liveness properties hold | 27,242 |
| `wide.cfg` | revoke, mixed, widen, breakglass | 2 | 3 | 1 | no | all invariants hold | 5,816,207 |
| `wide_liveness.cfg` | revoke, mixed, widen, breakglass | 2 | 2 | 1 | no | both liveness properties hold | 3,183,628 |
| `pendingfault_rest.cfg` | revoke, mixed, widen, breakglass | 2 | 3 | 1 | yes | every invariant except the two "no loss" ones holds | 12,286,765 |
| `pendingfault_gap.cfg` | revoke, widen, breakglass | 1 | 3 | 0 | yes | `NoUnrecordedEffect` violated (known, loud gap) | 205 |
| `pendingfault_silent.cfg` | revoke, widen, breakglass | 1 | 3 | 1 | yes | `NoSilentLoss` violated (silent gap, see Findings) | 221 |
| `explore_effect_order.cfg` | mixed, revoke | 1 | 2 | 0 | no | `EffectOrderIsChainOrder` violated (by design, see Findings) | 349 |
| `bug_widen_owed.cfg` | revoke, widen | 1 | 2 | 0 | no | seeded bug 1: `WideningFailClosed` violated | 23 |
| `bug_mixed_fail_closed.cfg` | mixed | 1 | 1 | 0 | no | seeded bug 2: `RevocationNeverBlocked` violated (temporal) | 9 |
| `bug_claim_split.cfg` | revoke | 2 | 2 | 0 | no | seeded bug 3: `ChainValid` violated | 136 |
| `bug_backfill_any_order.cfg` | revoke | 1 | 2 | 0 | no | seeded bug 4: `OwedOrderPreserved` violated | 104 |

For a violated configuration, "distinct states" is the count when TLC
stopped at the first counterexample.

"Small first, then widen": `small.cfg` came first. `wide.cfg` adds the mixed
request, the extra flip and the larger population. A wide configuration
with a fifth request (an ordinary audited write) was tried and stopped
unfinished after 19 million states. That write takes the same action as a
grant, so it adds states but no behaviour.

## What the model encodes, and where it comes from

| Model | Code | Rule |
|---|---|---|
| `CommitOwed`: the change and one `pending_audit_events` record per owed row in one transaction; no `auditUp` guard; collect-only fallback (`pid = 0`) when the record insert fails | `runOwedAuditMutation`, `recordOwedOn`, `commitOwingAudit` (`internal/core/audit_owed.go`) | ADR-112 Amendment 6 ("revocations stay never-blocked"); INV-CORE-revocation-audit-owed; INV-CORE-plain-suspend-audit-owed |
| `Evict` before `SettleRow` | `runOwedAuditMutation` returns `settle`, called after the auth-cache eviction | INV-CORE-revocation-audit-owed ("settle is called last") |
| `SettleRow`: claim and append in one step; the first refusal ends the attempts; rows without a record are queued late, else `lostLogged` | `settleOwedAudit`, `writeOwedAudit`, `appendOwedAudit`, `queueOwedAuditLate`, `noteOwedAuditNotAttempted` | INV-CORE-revocation-audit-owed (SUPERFAN-1022 note 1; the "NOT queued for backfill" gap) |
| `CommitAudited` / `WidenOrWrite`: effect and rows in one transaction, only if the audit log accepts them | `withAuditedMutation`, `failClosedAuditResult` (`mutation_audit_tx.go`) | INV-CORE-security-mutation-audit-same-tx; INV-CORE-secret-mutation-audit-same-tx |
| `CommitOwed` (part `c1`) then `Evict`, `SettleRow`, `CommitRemainder` (part `c2`); `partial` state and `Retry` | `audit_split.go` (`commitSplitRemainder`, `PartialMutationError`) | INV-CORE-mixed-request-split (ask 3482-mixed-request-rule (a)) |
| `BreakGlass`: normal path fail closed; degraded path commits grant + records tagged with the activation; else `refused` | `activateBreakGlassLocked`, `activateBreakGlassDegraded` (`break_glass.go`) | ADR-112 Amendment 6, "Normal path unchanged" / "Degraded path" |
| `List` / `Write`: oldest record first; claim, settle-if-last and append in one step; a refusal ends the pass; any number of replicas | `BackfillPendingAuditEvents`, `appendOwedAudit`, `SettleBreakGlassOwedAudit` (`local_break_glass.go`), `ClaimPendingAuditEvent` | ADR-112 Amendment 6, "Backfill" ("in the order they were owed", "exactly once", settled "in the same transaction as its last row") |
| `VerifierVerdict` | `checkOwedBreakGlass` (`internal/auditverify/owed_break_glass.go`) | ADR-112 Amendment 6 (`verify-audit` INDETERMINATE while any is unsettled) |
| `auditUp` | an append that errors, panics or misses the chain-lock bound | ADR-112 Amendment 6 ("an error, a panic, or the chain lock not coming within ... 10 s") |
| `Crash` | process death and restart; committed rows survive | INV-CORE-revocation-audit-owed ("a crash between the commit and the append loses nothing") |

## Properties

| Property | Statement | Brief item |
|---|---|---|
| `RevocationNeverBlocked` (liveness) | every revoke or mixed request ends with its narrowing in force (or its process crashed), even when the audit log never comes back | revocation never blocked |
| `NoUnrecordedEffect` | every row owed by a committed effect is in the chain, in `pending_audit_events`, or held by the live request about to write it | no unrecorded effect |
| `NoSilentLoss` | as above, or logged as "NOT queued for backfill" | (separates the loud gap from a silent one) |
| `WideningFailClosed` | a committed grant, write, mixed remainder or normal break-glass has its rows in the chain; a degraded break-glass has them in the chain or the ledger | widening fail closed |
| `ChainValid` | every entry links to its predecessor; no row twice; no row without its effect | hash chain valid |
| `CompleteAfterBackfill` | audit up, nothing pending, nothing in flight ⇒ chain = effects, chain valid, every degraded activation settled | hash chain valid after backfill |
| `OwedOrderPreserved` | rows of one commit reach the chain in the order they were owed | Amendment 6 order |
| `NarrowingFirst` | a mixed request's remainder commits only after its narrowing is in force; settle never precedes eviction | split order |
| `BreakGlassSettlementSound` | settled ⇒ all rows in the chain; `VERIFIED` ⇒ no degraded activation missing rows | verifier verdict |
| `BackfillConverges` (liveness) | once the audit log stays up, the owed ledger drains | backfill completes |

## Seeded bugs

`Bug` selects one; each has its own configuration. TLC must find each one.

1. `widen_owed`: a grant takes the owed path, so it commits during an outage.
   Found as `WideningFailClosed`.
2. `mixed_fail_closed`: a mixed request takes one direction for the whole
   call, so all of it fails closed. This is the shape REVIEW-3482 F1 found
   by hand before MERGE-FIX-3482G. Found as a `RevocationNeverBlocked`
   lasso: the audit log stays down and the request retries for ever.
3. `claim_split`: the backfill appends and claims in two transactions, so
   two replicas (or a replica and the request's own settle) write a row
   twice. Found as `ChainValid` (`ExactlyOnce`).
4. `backfill_any_order`: the backfill takes any pending record, not the
   oldest. Found as `OwedOrderPreserved`.

## Findings

1. **The brief's four properties hold within the bounds.** This covers
   every configuration without a seeded bug and with the owed-ledger table
   available (`small`, `wide`, `wide_liveness`):
   - revocation never blocked (liveness, with the audit log allowed to stay
     down for ever);
   - no unrecorded effect;
   - chain valid and complete after the backfill;
   - widening fail closed.

   Ordering, verifier soundness and convergence hold as well. With a crash
   allowed, they still hold, because the owed records commit with the
   effect.
2. **Known, loud gap: confirmed.** In `pendingfault_gap.cfg` the
   `pending_audit_events` insert fails during the revocation's transaction
   (the collect-only fallback). The audit log is also down at settle time,
   and the late queue fails too. The revocation then applies and its rows
   are only logged as "NOT queued for backfill". TLC reports
   `NoUnrecordedEffect` in 6 states. This is the documented gap in
   INV-CORE-revocation-audit-owed: it needs two faults and is loud.
3. **New: a silent variant of that gap.** `pendingfault_silent.cfg` finds
   it in 5 states. The pending insert fails, the revocation commits through
   the collect-only fallback, and the process crashes before settle. The
   owed rows lived only in process memory, so they are gone with no log
   line, no counter, and no pending record. `NoSilentLoss` is violated.
   Neither `CommitOwed` nor `Crash` reads `auditUp`, so this needs no audit
   outage at all: only the pending-insert fault and a crash. A wait for the
   audit log (`owedAuditWait`, 5 s) widens the window. The invariant text
   says "a crash between the commit and the append loses nothing: the
   record committed with the effect". That holds on the normal path only.
   The fault it needs (`pending_audit_events` refusing an insert while the
   same database commits the revocation) is unlikely but is the case the
   fallback exists for. This model does not change the code; the report
   routes it as a question.
4. **By design, worth stating: chain order is not effect order.**
   `explore_effect_order.cfg` (a 9-state trace) shows a revocation's owed row
   landing in the chain after the row of a later effect. Inside ONE mixed
   request, TLC also finds the remainder's row (for example the email
   change) appended before the narrowing's row (the deactivation):
   1. commit 1 under an outage;
   2. its settle is refused;
   3. the audit log returns;
   4. commit 2 commits with its row;
   5. the backfill writes commit 1's row afterwards.

   The backfill stamps a non-break-glass row with the backfill time as
   `event_time` and keeps the original time only in the description, so a
   reader of the chain sees the deactivation after the email change.
   ADR-112 Amendment 6's "in the order they were owed" is true, and
   `OwedOrderPreserved` checks it, but only among owed rows of one commit.
5. **The properties are not vacuous.** Each seeded bug is found, with traces of 3 to 6
   states. The mixed-request one (bug 2) is the defect REVIEW-3482 F1 found
   by reading code; TLC finds it as a 3-state lasso.

## What the model does not cover

- **Hashes.** A chain entry links to the previous index. Hash computation,
  canonical encoding and the verifier's walk are not modelled. They are
  covered by `internal/auditverify` tests, not by this model.
- **Durability levels.** Every committed transaction is durable. ADR-112
  Amendment 3's `standard` level (an OS crash can lose a tail of up to
  ~600 ms of async-committed audit rows) is not modelled. Owed appends and
  revocations run in transaction-scoped stores that never relax the sync,
  but successful reads at `standard` can lose their rows.
- **Several auth caches.** There is one cache, cold after a restart.
  Eviction across replicas is not modelled.
- **Time.** There are no clocks: no `owedAuditWait` (5 s) or chain-lock
  (10 s) bounds, no `degraded_ttl` expiry, no review deadline, and no
  original-time-versus-backfill-time rule (`event_time`). Only orderings
  are modelled.
- **Payloads.** An undecodable pending record is skipped by the real
  backfill, which then writes later rows first. This is not modelled.
- **Lost commit acknowledgement.** An append that committed but reported an
  error can be written twice through `queueOwedAuditLate` (documented in
  `audit_owed.go`). The model's appends report truthfully.
- **Database semantics.** PostgreSQL transaction aborts (REVIEW-3482 F2/F4),
  isolation levels, advisory locks and SQLite `BEGIN IMMEDIATE` are not
  modelled. Each modelled transaction is one atomic step.
- **Every revocation site.** The model has one generic revocation (two rows)
  and one generic mixed request. Whether each of the ~35 call sites uses the
  owed path is checked by the core and faultops tests, not here.
- **Retention, purge, SIEM forwarding, notifications, metrics.** Not
  modelled.
- **Bounds.** At most 4 requests, 2 replicas, 3 availability flips, 1 crash.
  Nothing is proven beyond them.
