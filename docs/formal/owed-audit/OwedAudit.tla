------------------------------ MODULE OwedAudit ------------------------------
(***************************************************************************)
(* A model of Keyorix's owed-audit design: how a security-relevant change  *)
(* and its audit row commit when the audit log may be refusing writes.     *)
(*                                                                         *)
(* What it encodes (docs/formal/owed-audit/README.md maps each item to its source):   *)
(*  - ADR-112 Amendment 6 and INV-CORE-revocation-audit-owed: a revocation *)
(*    commits with a pending_audit_events record of each row it owes,     *)
(*    never waiting for the audit log; after the auth-cache eviction the   *)
(*    rows are appended and their records claimed in one transaction; the  *)
(*    first refusal stops the attempts; a row whose record could not be    *)
(*    written is queued late, or logged as lost (audit_owed.go).           *)
(*  - INV-CORE-security-mutation-audit-same-tx: a widening (grant) or an   *)
(*    ordinary audited write commits with its audit row in one            *)
(*    transaction, or not at all (mutation_audit_tx.go).                   *)
(*  - INV-CORE-mixed-request-split (ask 3482-mixed-request-rule (a)): a    *)
(*    request that narrows and widens is two commits, narrowing first      *)
(*    (audit_split.go).                                                    *)
(*  - ADR-112 Amendment 6 (break-glass): the normal activation is fail     *)
(*    closed; when only the audit append fails, a degraded transaction     *)
(*    commits the grant with owed records, or the activation is refused.   *)
(*    The backfill settles the activation with its last row; the verifier  *)
(*    is INDETERMINATE while one is unsettled (owed_break_glass.go).       *)
(*  - BackfillPendingAuditEvents: oldest record first, claim and append in *)
(*    one transaction, stop at the first refusal, any number of replicas.  *)
(*                                                                         *)
(* What it abstracts (see README "What the model does not cover"): hashes  *)
(* are modelled as a link to the previous index; one database, every       *)
(* committed transaction durable (Amendment 3's `standard` tail loss is    *)
(* out of scope); one auth cache, cold after a restart; no clocks, TTLs or *)
(* event times; payload decode failures; the 5 s / 10 s bounds.            *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Kind,          \* sequence of request kinds: "revoke", "widen", "write", "mixed", "breakglass"
    Workers,       \* backfill replicas (model values)
    MaxFlips,      \* bound on availability changes of the audit log and the pending table
    MaxCrashes,    \* bound on process crashes (crash + immediate restart)
    PendingFault,  \* TRUE: pending_audit_events may also refuse inserts (second, independent fault)
    Bug            \* "none", or the name of one seeded bug (see README)

ASSUME Bug \in {"none", "widen_owed", "mixed_fail_closed", "claim_split", "backfill_any_order"}
ASSUME PendingFault \in BOOLEAN
ASSUME MaxFlips \in Nat /\ MaxCrashes \in Nat

Reqs == 1..Len(Kind)
NoBG == 0                                   \* "not owed by a degraded break-glass activation"
NoRec == [id |-> 0, row |-> <<0, 0>>, bg |-> NoBG]

(* The audit rows each part of a request writes, in order. A revocation and *)
(* a break-glass activation write two rows (e.g. user.deactivated +        *)
(* sessions.revoked; role.assigned + break_glass.activated) so that "the   *)
(* first refusal stops the attempts" and "settled with its last row" are   *)
(* exercised. A mixed request's narrowing part (c1) and remainder (c2)     *)
(* write one row each.                                                     *)
Parts(r) == IF Kind[r] = "mixed" THEN {"c1", "c2"} ELSE {"main"}
RowNums(r, p) ==
    CASE Kind[r] \in {"revoke", "breakglass"} -> <<1, 2>>
      [] Kind[r] = "mixed" /\ p = "c1"        -> <<1>>
      [] Kind[r] = "mixed" /\ p = "c2"        -> <<2>>
      [] OTHER                                -> <<1>>
RowSeq(r, p) == [i \in 1..Len(RowNums(r, p)) |-> <<r, RowNums(r, p)[i]>>]
RowSet(r, p) == {RowSeq(r, p)[i] : i \in 1..Len(RowSeq(r, p))}
PartOfRow(row) == IF Kind[row[1]] = "mixed" /\ row[2] = 2 THEN "c2"
                  ELSE IF Kind[row[1]] = "mixed" THEN "c1" ELSE "main"

Narrowing(r, p) == Kind[r] = "revoke" \/ (Kind[r] = "mixed" /\ p = "c1")
NarrowingReqs == {r \in Reqs : Kind[r] \in {"revoke", "mixed"}}
\* Parts that must be fail closed: every grant, every ordinary audited write,
\* the remainder of a mixed request, a (normal) break-glass activation.
FailClosedPart(r, p) == ~Narrowing(r, p)

VARIABLES
    auditUp,     \* the audit log accepts appends
    pendingUp,   \* pending_audit_events accepts inserts
    flips,       \* availability changes used
    crashes,     \* crashes used
    pc,          \* request control state
    applied,     \* [Reqs -> SUBSET parts]: committed effects
    inForce,     \* [Reqs -> BOOLEAN]: a committed narrowing is visible to the next request (cache evicted)
    effLog,      \* sequence of rows in the order their EFFECTS committed (ground truth)
    chain,       \* the audit hash chain: sequence of [row, prev]
    pending,     \* pending_audit_events: set of [id, row, bg]
    nextId,      \* next pending_audit_events id (ids only grow)
    sink,        \* [Reqs -> Seq([row, pid])]: owed rows held in process memory until settled
    lostLogged,  \* rows logged "NOT queued for backfill (record it by hand)"
    bgDegraded,  \* [Reqs -> BOOLEAN]: break-glass committed on the degraded path
    bgSettled,   \* [Reqs -> BOOLEAN]: audit_settled_at set
    wk           \* [Workers -> [st, rec]]: backfill replicas

vars == <<auditUp, pendingUp, flips, crashes, pc, applied, inForce, effLog, chain,
          pending, nextId, sink, lostLogged, bgDegraded, bgSettled, wk>>

PCs == {"start", "evict", "settle", "c2", "done", "failed", "partial", "refused", "crashed"}
Terminal == {"done", "failed", "partial", "refused", "crashed"}

-----------------------------------------------------------------------------
(* Helpers *)

RECURSIVE AppendAll(_, _)
\* Append rows to the chain; each entry links to the one before it (the hash).
AppendAll(ch, rs) ==
    IF rs = <<>> THEN ch
    ELSE AppendAll(Append(ch, [row |-> Head(rs), prev |-> Len(ch)]), Tail(rs))

ChainRows == {chain[i].row : i \in 1..Len(chain)}
PendingIds == {e.id : e \in pending}
PendingRows == {e.row : e \in pending}
InFlight == UNION {{sink[r][i].row : i \in 1..Len(sink[r])} : r \in Reqs}
EffectRows == UNION {UNION {RowSet(r, p) : p \in applied[r]} : r \in Reqs}

NewRecs(rs, bg) == {[id |-> nextId + i - 1, row |-> rs[i], bg |-> bg] : i \in 1..Len(rs)}

\* After the claim of one break-glass record: settled iff none of its records remain
\* (SettleBreakGlassOwedAudit, same transaction as the append).
SettleIfLast(newPending, bg) ==
    IF bg = NoBG \/ \E f \in newPending : f.bg = bg THEN bgSettled
    ELSE [bgSettled EXCEPT ![bg] = TRUE]

AfterSettle(r) == IF Kind[r] = "mixed" /\ "c2" \notin applied[r] THEN "c2" ELSE "done"

UsesOwedPath(r) ==
    \/ Kind[r] = "revoke"
    \/ Kind[r] = "mixed" /\ Bug # "mixed_fail_closed"
    \/ Kind[r] \in {"widen", "write"} /\ Bug = "widen_owed"   \* SEEDED BUG 1

-----------------------------------------------------------------------------
(* Initial state *)

Init ==
    /\ auditUp = TRUE
    /\ pendingUp = TRUE
    /\ flips = 0
    /\ crashes = 0
    /\ pc = [r \in Reqs |-> "start"]
    /\ applied = [r \in Reqs |-> {}]
    /\ inForce = [r \in Reqs |-> FALSE]
    /\ effLog = <<>>
    /\ chain = <<>>
    /\ pending = {}
    /\ nextId = 1
    /\ sink = [r \in Reqs |-> <<>>]
    /\ lostLogged = {}
    /\ bgDegraded = [r \in Reqs |-> FALSE]
    /\ bgSettled = [r \in Reqs |-> FALSE]
    /\ wk = [w \in Workers |-> [st |-> "idle", rec |-> NoRec]]

-----------------------------------------------------------------------------
(* Environment: audit outage, pending-table outage, process crash *)

AuditFlip ==
    /\ flips < MaxFlips
    /\ auditUp' = ~auditUp
    /\ flips' = flips + 1
    /\ UNCHANGED <<pendingUp, crashes, pc, applied, inForce, effLog, chain, pending,
                   nextId, sink, lostLogged, bgDegraded, bgSettled, wk>>

PendingFlip ==
    /\ PendingFault
    /\ flips < MaxFlips
    /\ pendingUp' = ~pendingUp
    /\ flips' = flips + 1
    /\ UNCHANGED <<auditUp, crashes, pc, applied, inForce, effLog, chain, pending,
                   nextId, sink, lostLogged, bgDegraded, bgSettled, wk>>

\* The process dies and restarts at once. Committed rows survive; in-memory sinks and
\* backfill progress do not. In-flight requests end; the restarted process has a cold
\* auth cache, so a committed narrowing is in force from then on.
Crash ==
    /\ crashes < MaxCrashes
    /\ LET live == {r \in Reqs : pc[r] \in {"evict", "settle", "c2"}} IN
       /\ pc' = [r \in Reqs |-> IF r \in live THEN "crashed" ELSE pc[r]]
       /\ sink' = [r \in Reqs |-> IF r \in live THEN <<>> ELSE sink[r]]
       /\ inForce' = [r \in Reqs |-> inForce[r] \/ (r \in live /\ \E p \in applied[r] : Narrowing(r, p))]
    /\ wk' = [w \in Workers |-> [st |-> "idle", rec |-> NoRec]]
    /\ crashes' = crashes + 1
    /\ UNCHANGED <<auditUp, pendingUp, flips, applied, effLog, chain, pending, nextId,
                   lostLogged, bgDegraded, bgSettled>>

-----------------------------------------------------------------------------
(* Requests *)

\* runOwedAuditMutation: the change and a pending record of each owed row commit in
\* ONE transaction. Not guarded by auditUp: the audit log cannot block it. If the
\* record insert fails, the change is re-run with a collect-only target and commits
\* without records (the rows stay in memory, pid 0).
CommitOwed(r) ==
    /\ pc[r] = "start"
    /\ UsesOwedPath(r)
    /\ LET p  == IF Kind[r] = "mixed" THEN "c1" ELSE "main"
           rs == RowSeq(r, p) IN
       /\ applied' = [applied EXCEPT ![r] = @ \cup {p}]
       /\ effLog' = effLog \o rs
       /\ IF pendingUp
            THEN /\ pending' = pending \cup NewRecs(rs, NoBG)
                 /\ nextId' = nextId + Len(rs)
                 /\ sink' = [sink EXCEPT ![r] = [i \in 1..Len(rs) |-> [row |-> rs[i], pid |-> nextId + i - 1]]]
            ELSE /\ UNCHANGED <<pending, nextId>>
                 /\ sink' = [sink EXCEPT ![r] = [i \in 1..Len(rs) |-> [row |-> rs[i], pid |-> 0]]]
    /\ pc' = [pc EXCEPT ![r] = "evict"]
    /\ UNCHANGED <<auditUp, pendingUp, flips, crashes, inForce, chain, lostLogged,
                   bgDegraded, bgSettled, wk>>

\* The auth-cache eviction: the narrowing is in force for the next request. It comes
\* BEFORE settle, so a slow or refusing audit log never delays it.
Evict(r) ==
    /\ pc[r] = "evict"
    /\ inForce' = [inForce EXCEPT ![r] = TRUE]
    /\ pc' = [pc EXCEPT ![r] = "settle"]
    /\ UNCHANGED <<auditUp, pendingUp, flips, crashes, applied, effLog, chain, pending,
                   nextId, sink, lostLogged, bgDegraded, bgSettled, wk>>

\* settleOwedAudit / writeOwedAudit / appendOwedAudit: one owed row per step. Claim and
\* append are one transaction. The first refusal ends the attempts: rows with a record
\* stay pending; rows without one are queued late (queueOwedAuditLate) or, if that
\* insert fails too, logged as NOT queued.
SettleRow(r) ==
    /\ pc[r] = "settle"
    /\ IF sink[r] = <<>>
         THEN /\ pc' = [pc EXCEPT ![r] = AfterSettle(r)]
              /\ UNCHANGED <<chain, pending, nextId, sink, lostLogged, bgSettled>>
         ELSE LET e == Head(sink[r]) IN
              IF auditUp
                THEN /\ IF e.pid = 0
                          THEN /\ chain' = AppendAll(chain, <<e.row>>)
                               /\ UNCHANGED pending
                          ELSE IF e.pid \in PendingIds
                            THEN /\ chain' = AppendAll(chain, <<e.row>>)
                                 /\ pending' = {f \in pending : f.id # e.pid}
                            ELSE UNCHANGED <<chain, pending>>   \* a backfill wrote it first
                     /\ sink' = [sink EXCEPT ![r] = Tail(@)]
                     /\ UNCHANGED <<pc, nextId, lostLogged, bgSettled>>
                ELSE LET late == SelectSeq(sink[r], LAMBDA x : x.pid = 0)
                         lrs  == [i \in 1..Len(late) |-> late[i].row] IN
                     /\ IF pendingUp
                          THEN /\ pending' = pending \cup NewRecs(lrs, NoBG)
                               /\ nextId' = nextId + Len(lrs)
                               /\ UNCHANGED lostLogged
                          ELSE /\ lostLogged' = lostLogged \cup {lrs[i] : i \in 1..Len(lrs)}
                               /\ UNCHANGED <<pending, nextId>>
                     /\ sink' = [sink EXCEPT ![r] = <<>>]
                     /\ pc' = [pc EXCEPT ![r] = AfterSettle(r)]
                     /\ UNCHANGED <<chain, bgSettled>>
    /\ UNCHANGED <<auditUp, pendingUp, flips, crashes, applied, inForce, effLog,
                   bgDegraded, wk>>

\* withAuditedMutation: the change and its audit rows in ONE transaction, or nothing.
CommitAudited(r, p, okPc, failPc) ==
    IF auditUp
      THEN /\ applied' = [applied EXCEPT ![r] = @ \cup {p}]
           /\ chain' = AppendAll(chain, RowSeq(r, p))
           /\ effLog' = effLog \o RowSeq(r, p)
           /\ pc' = [pc EXCEPT ![r] = okPc]
      ELSE /\ pc' = [pc EXCEPT ![r] = failPc]
           /\ UNCHANGED <<applied, chain, effLog>>

\* A grant or an ordinary audited write (secret write, role grant, share, ...).
WidenOrWrite(r) ==
    /\ pc[r] = "start"
    /\ Kind[r] \in {"widen", "write"}
    /\ ~UsesOwedPath(r)
    /\ CommitAudited(r, "main", "done", "failed")
    /\ UNCHANGED <<auditUp, pendingUp, flips, crashes, inForce, pending, nextId, sink,
                   lostLogged, bgDegraded, bgSettled, wk>>

\* commitSplitRemainder: commit 2 of a mixed request, fail closed. A failure leaves
\* commit 1 in force and answers PartialMutationError (503, retry_safe).
CommitRemainder(r) ==
    /\ pc[r] = "c2"
    /\ CommitAudited(r, "c2", "done", "partial")
    /\ UNCHANGED <<auditUp, pendingUp, flips, crashes, inForce, pending, nextId, sink,
                   lostLogged, bgDegraded, bgSettled, wk>>

\* SEEDED BUG 2 (the pre-MERGE-FIX-3482G shape, REVIEW-3482 F1): a mixed request
\* takes ONE direction for the whole call; because it widens, all of it fails closed.
MixedWhole(r) ==
    /\ pc[r] = "start"
    /\ Kind[r] = "mixed"
    /\ Bug = "mixed_fail_closed"
    /\ IF auditUp
         THEN /\ applied' = [applied EXCEPT ![r] = {"c1", "c2"}]
              /\ chain' = AppendAll(chain, RowSeq(r, "c1") \o RowSeq(r, "c2"))
              /\ effLog' = effLog \o RowSeq(r, "c1") \o RowSeq(r, "c2")
              /\ pc' = [pc EXCEPT ![r] = "evict"]
         ELSE /\ pc' = [pc EXCEPT ![r] = "failed"]
              /\ UNCHANGED <<applied, chain, effLog>>
    /\ UNCHANGED <<auditUp, pendingUp, flips, crashes, inForce, pending, nextId, sink,
                   lostLogged, bgDegraded, bgSettled, wk>>

\* activateBreakGlassLocked: normal path fail closed; if only the audit append failed,
\* activateBreakGlassDegraded commits grant + owed records (tagged with the activation)
\* in one transaction, or the activation is refused (BreakGlassUnrecordable).
BreakGlass(r) ==
    /\ pc[r] = "start"
    /\ Kind[r] = "breakglass"
    /\ LET rs == RowSeq(r, "main") IN
       IF auditUp
         THEN /\ applied' = [applied EXCEPT ![r] = {"main"}]
              /\ chain' = AppendAll(chain, rs)
              /\ effLog' = effLog \o rs
              /\ pc' = [pc EXCEPT ![r] = "done"]
              /\ UNCHANGED <<pending, nextId, bgDegraded>>
         ELSE IF pendingUp
           THEN /\ applied' = [applied EXCEPT ![r] = {"main"}]
                /\ effLog' = effLog \o rs
                /\ pending' = pending \cup NewRecs(rs, r)
                /\ nextId' = nextId + Len(rs)
                /\ bgDegraded' = [bgDegraded EXCEPT ![r] = TRUE]
                /\ pc' = [pc EXCEPT ![r] = "done"]
                /\ UNCHANGED chain
           ELSE /\ pc' = [pc EXCEPT ![r] = "refused"]
                /\ UNCHANGED <<applied, effLog, chain, pending, nextId, bgDegraded>>
    /\ UNCHANGED <<auditUp, pendingUp, flips, crashes, inForce, sink, lostLogged,
                   bgSettled, wk>>

\* The client retries. A mixed request's retry re-runs commit 1 as a no-op (idempotent)
\* and only commit 2 has work left.
Retry(r) ==
    /\ pc[r] \in {"failed", "partial"}
    /\ pc' = [pc EXCEPT ![r] = IF @ = "partial" THEN "c2" ELSE "start"]
    /\ UNCHANGED <<auditUp, pendingUp, flips, crashes, applied, inForce, effLog, chain,
                   pending, nextId, sink, lostLogged, bgDegraded, bgSettled, wk>>

ReqStep(r) ==
    \/ CommitOwed(r) \/ Evict(r) \/ SettleRow(r)
    \/ WidenOrWrite(r) \/ CommitRemainder(r) \/ MixedWhole(r) \/ BreakGlass(r)
    \/ Retry(r)

-----------------------------------------------------------------------------
(* Backfill replicas (BackfillPendingAuditEvents) *)

\* Read the oldest pending record (SEEDED BUG 4: any record).
List(w) ==
    /\ wk[w].st = "idle"
    /\ pending # {}
    /\ LET cand == IF Bug = "backfill_any_order" THEN pending
                   ELSE {e \in pending : \A f \in pending : e.id <= f.id} IN
       \E e \in cand : wk' = [wk EXCEPT ![w] = [st |-> "listed", rec |-> e]]
    /\ UNCHANGED <<auditUp, pendingUp, flips, crashes, pc, applied, inForce, effLog,
                   chain, pending, nextId, sink, lostLogged, bgDegraded, bgSettled>>

\* appendOwedAudit: claim (DELETE ... reporting whether this call removed it), settle
\* the break-glass activation if this was its last row, append; one transaction. A
\* refused append ends the pass; a record already claimed means another writer won.
\* SEEDED BUG 3: append now, claim in a later, separate transaction.
Write(w) ==
    /\ wk[w].st = "listed"
    /\ LET e == wk[w].rec IN
       IF ~auditUp \/ e.id \notin PendingIds
         THEN /\ wk' = [wk EXCEPT ![w] = [st |-> "idle", rec |-> NoRec]]
              /\ UNCHANGED <<chain, pending, bgSettled>>
         ELSE IF Bug = "claim_split"
           THEN /\ chain' = AppendAll(chain, <<e.row>>)
                /\ wk' = [wk EXCEPT ![w] = [st |-> "appended", rec |-> e]]
                /\ UNCHANGED <<pending, bgSettled>>
           ELSE LET np == {f \in pending : f.id # e.id} IN
                /\ chain' = AppendAll(chain, <<e.row>>)
                /\ pending' = np
                /\ bgSettled' = SettleIfLast(np, e.bg)
                /\ wk' = [wk EXCEPT ![w] = [st |-> "idle", rec |-> NoRec]]
    /\ UNCHANGED <<auditUp, pendingUp, flips, crashes, pc, applied, inForce, effLog,
                   nextId, sink, lostLogged, bgDegraded>>

Claim(w) ==
    /\ wk[w].st = "appended"
    /\ LET e == wk[w].rec
           np == {f \in pending : f.id # e.id} IN
       /\ pending' = np
       /\ bgSettled' = IF e.id \in PendingIds THEN SettleIfLast(np, e.bg) ELSE bgSettled
    /\ wk' = [wk EXCEPT ![w] = [st |-> "idle", rec |-> NoRec]]
    /\ UNCHANGED <<auditUp, pendingUp, flips, crashes, pc, applied, inForce, effLog,
                   chain, nextId, sink, lostLogged, bgDegraded>>

WorkerStep(w) == List(w) \/ Write(w) \/ Claim(w)

-----------------------------------------------------------------------------
\* Every request has finished and nothing is left for the backfill: stutter (not a deadlock).
Done ==
    /\ \A r \in Reqs : pc[r] \in Terminal
    /\ \A w \in Workers : wk[w].st = "idle"
    /\ pending = {}
    /\ UNCHANGED vars

Next ==
    \/ AuditFlip \/ PendingFlip \/ Crash \/ Done
    \/ \E r \in Reqs : ReqStep(r)
    \/ \E w \in Workers : WorkerStep(w)

\* Requests and replicas make progress; the environment does not have to (the audit
\* log may stay down for ever).
Fairness ==
    /\ \A r \in Reqs : WF_vars(ReqStep(r))
    /\ \A w \in Workers : WF_vars(WorkerStep(w))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Properties *)

TypeOK ==
    /\ auditUp \in BOOLEAN /\ pendingUp \in BOOLEAN
    /\ pc \in [Reqs -> PCs]
    /\ \A r \in Reqs : applied[r] \subseteq Parts(r)
    /\ inForce \in [Reqs -> BOOLEAN]
    /\ \A i \in 1..Len(chain) : chain[i].prev \in Nat
    /\ \A e \in pending : e.id \in 1..(nextId - 1)
    /\ bgDegraded \in [Reqs -> BOOLEAN] /\ bgSettled \in [Reqs -> BOOLEAN]
    /\ \A w \in Workers : wk[w].st \in {"idle", "listed", "appended"}

(* I1: no unrecorded effect. Every row owed by a committed effect is in the chain,  *)
(* in the owed ledger, or still held by the live request that is about to write or *)
(* queue it.                                                                       *)
NoUnrecordedEffect == EffectRows \subseteq (ChainRows \cup PendingRows \cup InFlight)

(* I1': weaker: a row may also be "logged as lost" (the documented both-writes-fail *)
(* gap). Used to separate a loud gap from a silent one.                            *)
NoSilentLoss == EffectRows \subseteq (ChainRows \cup PendingRows \cup InFlight \cup lostLogged)

(* I2: widening is fail closed. A committed fail-closed part has its rows in the   *)
(* chain. The one designed exception, a degraded break-glass activation, has its   *)
(* rows in the chain or in the owed ledger, never only in memory.                  *)
WideningFailClosed ==
    \A r \in Reqs : \A p \in applied[r] :
        FailClosedPart(r, p) =>
            IF bgDegraded[r] THEN RowSet(r, p) \subseteq (ChainRows \cup PendingRows)
            ELSE RowSet(r, p) \subseteq ChainRows

(* I3: the hash chain is valid: every entry links to its predecessor, no row is    *)
(* written twice, and no row describes an effect that did not commit.             *)
ChainLinked == \A i \in 1..Len(chain) : chain[i].prev = i - 1
ExactlyOnce == \A i, j \in 1..Len(chain) : i # j => chain[i].row # chain[j].row
NoPhantom == ChainRows \subseteq EffectRows
ChainValid == ChainLinked /\ ExactlyOnce /\ NoPhantom

(* I4: rows of one commit reach the chain in the order they were owed (Amendment 6). *)
OwedOrderPreserved ==
    \A i, j \in 1..Len(chain) :
        (i < j /\ chain[i].row[1] = chain[j].row[1]
               /\ PartOfRow(chain[i].row) = PartOfRow(chain[j].row))
            => chain[i].row[2] < chain[j].row[2]

(* I5: the narrowing half of a mixed request is in force before the remainder     *)
(* commits, and a revocation is in force before its rows are settled.             *)
NarrowingFirst ==
    \A r \in Reqs :
        /\ (Kind[r] = "mixed" /\ "c2" \in applied[r]) => ("c1" \in applied[r] /\ inForce[r])
        /\ (pc[r] = "settle") => inForce[r]

(* I6: break-glass settlement and the verifier verdict are sound.                 *)
VerifierVerdict == IF \E r \in Reqs : bgDegraded[r] /\ ~bgSettled[r] THEN "INDETERMINATE" ELSE "VERIFIED"
BreakGlassSettlementSound ==
    /\ \A r \in Reqs : bgSettled[r] => (bgDegraded[r] /\ RowSet(r, "main") \subseteq ChainRows)
    /\ VerifierVerdict = "VERIFIED" =>
         \A r \in Reqs : bgDegraded[r] => RowSet(r, "main") \subseteq ChainRows

(* I7: after the backfill has drained (audit up, nothing pending, nothing in       *)
(* flight), the trail is complete: every effect's rows in the chain exactly once,  *)
(* the chain valid, every degraded activation settled.                             *)
Quiescent ==
    /\ auditUp /\ pending = {}
    /\ \A r \in Reqs : pc[r] \in Terminal
    /\ \A w \in Workers : wk[w].st = "idle"
CompleteAfterBackfill ==
    Quiescent =>
        /\ EffectRows = ChainRows
        /\ ChainValid
        /\ \A r \in Reqs : bgDegraded[r] => bgSettled[r]

(* L1: a revocation is never blocked by an audit outage: even if the audit log      *)
(* never comes back, every narrowing request ends in force (or its process died    *)
(* before it committed anything visible to it).                                    *)
RevocationNeverBlocked ==
    \A r \in NarrowingReqs : <>(inForce[r] \/ (pc[r] = "crashed"))

(* L2: once the audit log stays up, the owed ledger drains.                        *)
BackfillConverges == (<>[]auditUp) => <>[](pending = {})

(* EXPLORATORY (expected to fail, see README): chain order equals effect order.    *)
EffectOrderIsChainOrder ==
    \A i, j \in 1..Len(chain) :
        i < j => \A a, b \in 1..Len(effLog) :
                    (effLog[a] = chain[i].row /\ effLog[b] = chain[j].row) => a < b
=============================================================================
