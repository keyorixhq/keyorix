# Design note: agent evidence ledger

Status: R&D design (RD-AGENT-LEDGER-1), 2026-10-23. Docs only, **nothing here
is implemented**. The decision record is
[ADR-118](adr-118-agent-evidence-ledger.md) (Proposed). This note adds what an
ADR should not carry: the mapping to external rules, the threat summary, the
plan for the formal model, a demo script, a one-page brief and the
implementation plan.

## 1. Summary of the mechanism

```
delegator (user / service)            agent (session credential kx_agent_…)            Keyorix server                    audit chain
──────────────────────────            ─────────────────────────────────────            ──────────────                    ───────────
POST /agent-sessions ───────────────────────────────────────────────────────────────▶ ceiling check, session row ──▶ agent.session_started (fail closed)
                                      POST /agent-sessions/{id}/intents ─────────────▶ intent row, uses_left ───────▶ agent.intent         (fail closed)
                                      GET secret + X-Keyorix-Agent-Intent ───────────▶ gate: open, target, uses ────▶ secret.read          (before release)
                                      ◀──────────────────────────────── value ───────
                                      POST /agent-intents/{id}/outcome ──────────────▶ close intent ────────────────▶ agent.outcome        (owed)
                                      (or nothing: agent died)                         sweeper at not_after+grace ──▶ agent.outcome_missing (owed)
auditor: GET /agent-ledger/export?nonce=… ──────────────────────────────────────────▶ ───────────────────────────────▶ agent_ledger.exported (fail closed)
auditor, offline: keyorix-server admin verify-audit --agent-bundle b.json --tsa-roots roots.pem --expect-nonce …
```

The owed-audit roles are reused as they are:

| Ledger step | Owed-audit role | Existing rule it inherits |
|---|---|---|
| session start, intent, export | widening: effect and row in one transaction, fail closed | INV-CORE-security-mutation-audit-same-tx; TLA+ `CommitAudited` / `WideningFailClosed` |
| release (value read) | audit-before-disclosure, plus the intent gate | ADR-112 Amendment 3; existing read path |
| outcome, missing outcome, session end/revoke | narrowing / post-effect: effect and `pending_audit_events` record in one transaction, append later, backfill exactly once in owed order | INV-CORE-revocation-audit-owed; ADR-112 Amendment 6 backfill; TLA+ `CommitOwed`, `SettleRow`, `Write` |
| verify while ledger rows are still owed | INDETERMINATE, never VERIFIED | ADR-112 Amendment 6 (`verify-audit` with unsettled break-glass) |

## 2. Field mapping to external rules

**How to read this table.** Keyorix is not itself an AI system, and this
mapping does not make it compliant with anything. It shows which ledger field
can serve as evidence for a logging duty that falls on the provider or
deployer of an AI system, or on a financial entity. Every claim about an
external text is marked:

- **[READ]**: read in this session, from the source named in §2.1;
- **[VERIFY]**: not read in this session. Stated from the brief or general
  knowledge, and to be checked against the official text before anyone relies
  on it.

No article, clause or section number is given unless it was read.

### 2.1 What was read, and from where (2026-10-23)

| Text | Status | Source actually read |
|---|---|---|
| EU AI Act (Regulation (EU) 2024/1689), Art. 12 "Record-keeping" | [READ], from a secondary site | `artificialintelligenceact.eu/article/12/`. The EUR-Lex page returned no text to the fetch tool, so the Official Journal text was not compared. The site's application dates for Art. 12 (2 Dec 2027 for Annex III systems, 2 Aug 2028 for Annex I) are [VERIFY]. |
| EU AI Act Art. 19 (automatically generated logs) and Art. 26(5)/(6) (deployer monitoring and log keeping) | [VERIFY] | not read; named because Art. 12(2)(c) refers to Art. 26(5) |
| `draft-sharif-agent-audit-trail-08` (IETF individual draft, 2026-10-13, "Agent Audit Trail: A Standard Logging Format for Autonomous AI Systems") | [READ] §§1–13.3, through the fetch tool | `datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/`. The page states that the draft has no IETF endorsement or formal standing. §13.4 onward and the appendices were not read. |
| prEN 18229-1:2026, "AI trustworthiness framework — Part 1: Logging" (CEN/CLC/JTC 21/WG 4) | title and scope only | DIN Media catalogue entry: "terminology, concepts, requirements, and guidance for logging in AI systems". The text is paywalled and not public; every requirement is [VERIFY]. The enquiry dates differ between sources. |
| ISO/IEC DIS 24970, "Artificial intelligence — AI system logging" | title and scope only | ISO / DIN catalogue entries: "common capabilities, requirements and an information model for logging events in AI systems". The text is paywalled. The stage differs between sources (DIS enquiry vs FDIS), and BSI lists BS EN ISO/IEC 24970 as published. Every requirement is [VERIFY]. |
| DORA (Regulation (EU) 2022/2554) and its RTS on the ICT risk-management framework (Commission Delegated Regulation (EU) 2024/1774) | [VERIFY] | not read: EUR-Lex returned no text to the fetch tool. That the RTS has a logging article covering what is logged, log protection, retention and time synchronisation is general knowledge, not read here. |

### 2.2 AI Act Art. 12 ([READ], secondary source)

What was read: paragraph 1 requires that high-risk AI systems "technically
allow for the automatic recording of events (logs) over the lifetime of the
system". Paragraph 2 asks that logging enable recording of events relevant
for:

- (a) identifying situations that may result in a risk within the meaning of
  Art. 79(1), or a substantial modification;
- (b) post-market monitoring (Art. 72);
- (c) monitoring the operation (Art. 26(5)).

Paragraph 3 lists minimum content for Annex III point 1(a) (remote biometric)
systems: the start and end of each use, the reference database, the matching
input, and the natural persons who verified the results.

| Art. 12 element | Ledger field / mechanism | Fit |
|---|---|---|
| 12(1) automatic recording over the lifetime | server-written rows, not agent-written; chained; retention floor (ADR-118 §6) | supports the *secret-use* slice of an AI system's events only, not the model's own events |
| 12(2)(a) situations that may present a risk | `agent.outcome_missing`; denied `secret.read` with `agent_intent_*` reasons; `late` outcomes; intents with wide `targets` | evidence of anomalous credential use; deciding what is a "risk" stays with the provider |
| 12(2)(b) post-market monitoring | export bundle (`/agent-ledger/export`) and per-session completeness (`seq`, `last_seq`) | input to the provider's monitoring; not monitoring in itself |
| 12(2)(c) monitoring of operation by the deployer | `agent.session_started` (delegator, scope), `agent.intent` (purpose, targets), `reads_used` | deployer-side evidence of what the agent was allowed and declared |
| 12(3)(a) start and end of each use (biometric systems only) | `agent.session_started` / `agent.session_ended` event times | structurally analogous; para. 3 applies to Annex III 1(a) systems only |
| 12(3)(d) natural persons involved in verification | `delegator` when its type is `user` | analogous only; para. 3 is biometric-specific |
| Art. 19 / Art. 26(6) log keeping by providers / deployers | `agent_ledger.min_retention` default 6 months | [VERIFY] the duration, which is commonly cited for Art. 26(6) |

### 2.3 IETF `draft-sharif-agent-audit-trail-08` ([READ])

Mandatory fields (§3.1, read): `record_id`, `timestamp`, `agent_id`,
`principal` (`principal_type`, `principal_id`, `authority_ref`),
`agent_version`, `session_id`, `action_type`, `action_detail`, `outcome`,
`trust_level`, `parent_record_id`, `prev_hash`, `record_phase`.

| Draft field | Ledger source | Notes |
|---|---|---|
| `record_id` | audit row `id` (plus bundle id) | the draft's ids are per recorder; ours are chain ids |
| `timestamp` | `event_time` | an owed row keeps its original time, so chain order ≠ time order (TLA+ finding) |
| `agent_id` | `diff.agent.mi` (+ `name`) | |
| `principal.principal_type` / `principal_id` | `diff.delegator.type` / `id` | the draft's types are human, organization, service, agent; ours are `user`, `machine_identity` |
| `principal.authority_ref` | agent session id (+ `scope_digest`) | the draft: "a reference to the grant, delegation, or authorization under which the agent acted" |
| `agent_version` | `diff.agent_meta.agent_version` | agent-asserted |
| `session_id` | `diff.session` | |
| `action_type` / `action_detail` | `event_type` / the `diff` record | the draft's `tool_call` detail has `tool_name`, `parameters_hash`; ours has `tool` and `input_digest` |
| `outcome` | `diff.status` on `agent.outcome`; `denied` for refused reads | draft values: `success`, `failure`, `timeout`, `denied`, `escalated`. Our `outcome_missing` maps closest to `timeout`; `partial` and `abandoned` have no draft equivalent |
| `trust_level` (L0–L4) | not stored | derivable from session credential + server-side gate, but assigning a level is a policy claim. Decided (D8, Andrei 2026-10-23): not stored in the MVP; derived only in a future draft-shaped exporter |
| `parent_record_id` | `diff.intent` on read/outcome rows | |
| `prev_hash` | `prev_hash` | different canonicalisation: the draft hashes RFC 8785 JCS of the previous record; ours is the ADR-029 length-prefixed field encoding |
| `record_phase` | `agent.intent` = `pre_execution`; `secret.read` = `concurrent`; `agent.outcome` / `outcome_missing` = `post_execution` | the draft (§4.3) requires a `pre_execution` record before state-changing actions in high-risk systems; ours is enforced by the authority, not self-reported |
| optional `input_hash` / `output_hash` | `input_digest` / `output_digest` | the draft: SHA-256, "used instead of raw input to preserve privacy"; ADR-118 §6 recommends a keyed digest instead |
| optional `model_id` | `diff.agent_meta.model_id` | agent-asserted |
| optional `batch` (`merkle_root`, `leaf_index`, `inclusion_proof`) | tree mode of the export | both use the RFC 6962 / 9162 construction |
| optional `external_timestamp` | RFC 3161 token on the checkpoint / tree head | |
| optional `signature`, `sig_alg`, `signer_kid` (ES256 default, ML-DSA-65, hybrid) | not in MVP | needs an asymmetric server key (R8); HMAC checkpoints are not publicly verifiable |
| genesis / close / heartbeat / tombstone records (§8, §9.3) | `session_started` / `session_ended` with `last_seq`; no heartbeat; purges handled by retention anchors | |

A later exporter could emit draft-shaped JSON from the bundle. It cannot emit
the draft's per-record signatures until R8 provides a server signing key.

### 2.4 prEN 18229-1 and ISO/IEC DIS 24970 (scope only; every row [VERIFY])

Neither text was read. The rows below list what such a standard is *likely*
to ask a log to identify, so that a reader holding the text can check each
row. They are questions, not claims.

| Likely logging element [VERIFY] | Ledger field |
|---|---|
| event identity, type and time; time source | `id`, `event_type`, `event_time` (server clock; the TSA token gives an external time for the head) |
| the AI system / component and its version | `diff.agent`, `diff.agent_meta.agent_version`, `model_id` (asserted) |
| the responsible person or organisation | `diff.delegator`, project |
| inputs/outputs or references to them, privacy-preserving | `input_digest`, `output_digest`; no text by default |
| integrity and protection of logs | ADR-029 chain, checkpoints, RFC 3161, export bundle with offline verify |
| retention and access control for logs | ADR-118 §6; export gated by `audit.read` + `system.read` |
| an information model / schema | `kx-agent-v1` (ADR-118 §4) |

### 2.5 DORA ICT logging (every row [VERIFY])

| Likely logging element [VERIFY] | Ledger field |
|---|---|
| logging of access to ICT assets and of privileged/credential use | `secret.read` bound to an intent; session and delegation rows |
| protection of logs against tampering and unauthorised access | hash chain, checkpoints, anchors, offline verify |
| retention of logs in line with the entity's policy | audit retention plus the ledger floor |
| clock synchronisation | server clock; RFC 3161 time on anchors |
| detection of anomalous activity | `outcome_missing`, denied reads, counters, notification |

## 3. Threats

The threat rows are in
[`security/threat-models/agent-evidence-ledger.md`](security/threat-models/agent-evidence-ledger.md)
(AGL-1 to AGL-9). Every row is a GAP until the implementation lands, and
cites the test of the mechanism the design reuses. In short:

| Brief threat | Row | Design answer | What stays open |
|---|---|---|---|
| forged agent identity | AGL-1, AGL-2 | session credential bound to one session, short TTL; scope derived from the delegator's and the agent's authority, re-derived at every intent | a stolen credential works until the TTL ends or someone revokes it; no proof of possession in the MVP |
| intent without outcome | AGL-4 | every intent is owed a terminal row; the sweeper writes `agent.outcome_missing` through the owed path | the owed path's double-fault gap (#3656) |
| outcome without intent | AGL-5 | API refuses it; the verifier flags any outcome without an earlier intent | a lying outcome is undetectable |
| replay of an export | AGL-7 | export row with a caller nonce inside the bundle; coverage in the report; consistency with an earlier anchor | without a nonce, only authenticity is shown, not freshness |
| compromised agent host | AGL-6 | blast radius bounded and fully recorded | a released value cannot be recalled |
| chain truncation | AGL-8 | existing checkpoints and anchors; segment mode is complete; `seq` gaps in tree mode | open sessions in tree mode; a host admin before the last external anchor |

## 4. Extension plan for the TLA+ model (no model change in this PR)

The owed-audit model (`docs/formal/owed-audit/`, #3647) already has the
pieces the ledger reuses:

- the audit-log outage (`auditUp`);
- the pending-table fault (`pendingUp`, `PendingFault`);
- crashes;
- the owed commit, settle and backfill (`CommitOwed`, `SettleRow`, `List` /
  `Write`);
- the fail-closed commit (`CommitAudited`);
- the chain abstraction (`chain` as a sequence of `[row, prev]`).

The ledger should be added **to that model, not as a new one**, so that every
ledger property is checked under the same outage, fault and crash behaviour.
A separate copy of those actions would drift from the original (the drift
risk the owed-audit design note already names).

### 4.1 Model changes (next session)

| Change | Shape | Maps to |
|---|---|---|
| `Kind` value `"intent"` | one row, fail closed: takes the existing `WidenOrWrite` / `CommitAudited` path | `agent.intent` with `withAuditedMutation` |
| `Kind` value `"outcome"` with a constant `IntentOf[r]` | one row, owed: takes the existing `CommitOwed` path; the effect closes the intent | `agent.outcome` with `commitOwingAudit` |
| new variable `released` (`[Reqs -> Nat]`) and action `Release(i)` | guard: `Bug # "release_before_commit" => <<i, 1>> \in ChainRows` and the intent is open and `released[i] < MaxUses` | the read gate; the read row itself is abstracted as part of the release (audit-before-disclosure is already established) |
| new variable `agentGone` and action `AgentGone(i)` | the agent stops: no outcome request will run | agent crash or exit |
| action `Sweep(i)` | enabled when the intent is open and `agentGone[i]` (the deadline is abstracted as "the agent is gone"); commits the close plus the `outcome_missing` row through `CommitOwed` | the sweeper |
| operator `Verify(b)` over a bundle `b` (a subsequence of `chain` plus a pending count) | `"BROKEN"` if links are broken, a row appears twice, an outcome or release has no earlier intent, or `seq` has a gap; `"INDETERMINATE"` if pending > 0 or an intent is open; else `"VERIFIED"` | `verify-audit --agent-bundle` checks 1, 2 and 4 (ADR-118 §5); hashing is abstracted as row identity, as in `ChainLinked` |
| action `Tamper` on an exported copy only | drop, duplicate or reorder one row of `Export(h)` | AGL-8 |

### 4.2 Properties

| Property | Kind | Statement |
|---|---|---|
| `NoReleaseWithoutDurableIntent` | invariant | `\A i : released[i] > 0 => <<i, 1>> \in ChainRows`. A release implies that the intent row is in the chain (committed), not only in flight or pending |
| `TerminalRecordedOrOwed` | invariant | every closed intent's terminal row is in `ChainRows \cup PendingRows \cup InFlight`. This follows from `NoUnrecordedEffect` once closing is an owed effect; it is stated separately so that a counterexample names the ledger |
| `OutcomeEventuallyRecordedOrOwed` | liveness | `\A i : released[i] > 0 ~> (Terminal(i) \in ChainRows \cup PendingRows)`, under weak fairness of `Sweep`, even if the audit log never comes back |
| `ExportVerifiesOffline` | invariant | `\A h \in 1..Len(chain) : Verify(Export(h)) # "BROKEN"`: an honest chain never verifies as BROKEN; it is `"VERIFIED"` when `Quiescent` |
| `TamperDetected` | invariant (over `Tamper` states) | a tampered export never verifies as `"VERIFIED"` |
| `PairingOrder` | invariant | in chain order, an intent's row precedes every release bound to it and its terminal row (an owed outcome is appended late, but never before its intent, because the intent is fail closed) |

### 4.3 Seeded bugs (each must be found)

1. `release_before_commit`: the gate accepts an intent whose row is still in
   flight. Expected: `NoReleaseWithoutDurableIntent`, via a crash between the
   release and the commit.
2. `outcome_fail_closed`: the outcome takes the fail-closed path. Expected: a
   lasso in `OutcomeEventuallyRecordedOrOwed` with the audit log down and the
   agent gone (the sweeper fails closed too).
3. `sweep_without_record`: the sweeper closes the intent without the owed
   record. Expected: `TerminalRecordedOrOwed` with a crash before the append.
4. `verifier_ignores_seq`: `Verify` skips the `seq` gap check. Expected:
   `TamperDetected`, with a dropped row in tree mode.

### 4.4 Configurations to add

| Configuration | Population | Expected verdict |
|---|---|---|
| `agent_small.cfg` | intent, outcome, revoke; 2 replicas, 2 flips, 1 crash | every invariant and both liveness properties hold |
| `agent_wide.cfg` | 2 intents (one with an outcome, one abandoned), widen, revoke; 3 flips | every invariant holds |
| `agent_liveness.cfg` | as `agent_small` | `OutcomeEventuallyRecordedOrOwed`, `RevocationNeverBlocked`, `BackfillConverges` hold |
| `agent_pendingfault.cfg` | as `agent_small`, `PendingFault = TRUE` | `TerminalRecordedOrOwed` violated: the known, loud gap inherited from the owed path (until #3656's change is modelled) |
| `bug_release_before_commit.cfg`, `bug_outcome_fail_closed.cfg`, `bug_sweep_without_record.cfg`, `bug_verifier_ignores_seq.cfg` | the smallest population that shows each bug | the seeded property violated |

`run-tlc.sh` gets the new verdict rows, so a changed verdict fails the run.

### 4.5 What the model will not cover

- **Amendment 3's `standard` tail loss.** The model has no tail loss, so it
  cannot show the D2 risk (an intent and its reads lost together after a
  release). That risk is argued in prose (ADR-118 technical risks), not
  checked.
- **Time.** Deadlines, TTLs and `not_after` are abstracted as the "agent
  gone" event.
- **Hashes, Merkle proofs and signatures.** They are abstracted as row
  identity. The cryptography is checked by the verifier's own tests and fuzz
  targets.
- **Re-derived delegation.** Authorization is outside the model.

## 5. Prototype check (throwaway, not committed)

To check the record format against the existing chain verifier, a throwaway
Go program was written under `.scratch/agentproto/`. It is not committed. It
used the real `internal/auditverify.ComputeEntryHash` and
`EntryHashMatchesAnyKnownEncoding`, and nothing else from the repository. It
did the following:

- built 7 rows: 5 ledger rows (session start, intent, a bound `secret.read`,
  outcome, session end) between 2 unrelated rows;
- put `kx-agent-v1` objects in `diff`;
- chained the rows from genesis;
- checked the segment proof, a tree (RFC 9162 hashing) and the pairing rules.

Results:

| Check | Result |
|---|---|
| every row's `entry_hash` re-derives with the independent verifier hash, ledger `diff` included | pass. The format needs no encoding change |
| segment rows link from genesis | pass |
| one changed byte in an intent's `diff` no longer re-derives | pass |
| inclusion proofs for the 5 ledger rows reach the tree head | pass |
| a tampered row whose leaf is taken from its **stored** `entry_hash` still proves inclusion | as expected. This is why ADR-118 §5 check 2 derives the leaf from the fields |
| the same tampered row with its leaf **derived** fails inclusion | pass |
| a tree bundle with the outcome left out | caught three ways: no terminal record, a `seq` gap, and `last_seq` ≠ count |
| an outcome with no earlier intent | caught |

The prototype also showed that owed rows reach the chain after later rows.
Checking `seq` in chain order would therefore raise false gaps, so ADR-118 §4
compares `seq` as a set. The prototype did not measure performance and
supports no number.

## 6. Demo script (≤ 5 minutes) — NOT IMPLEMENTED

**Every command below is a future CLI or API. None of it exists today.** It
is the acceptance demo for the implementation (R6: "agent uses a secret →
intent + outcome recorded → export verified offline"). Command names follow
ADR-118 and may change with the CLI-UX-2 conventions.

| Time | Step | Command (future) | What the audience sees |
|---|---|---|---|
| 0:00 | Setup: an `agent` identity with a project viewer role | `keyorix machine-identity create deploy-bot --project shop --type agent` then `keyorix machine-identity role grant deploy-bot project_viewer --project shop` | an identity of type `agent`; no token yet |
| 0:40 | A human delegates a 15-minute run | `keyorix agent session start deploy-bot --scope 'secrets.read:prod/*' --ttl 15m --task-ref DEPLOY-42` | a session id and a `kx_agent_…` credential shown once; `agent.session_started` in `keyorix audit list --type 'agent.*'` |
| 1:20 | The agent reads without an intent: refused | `KEYORIX_TOKEN=$KX_AGENT keyorix secret get prod/db-password` | `403 agent_intent_required`; a denied `secret.read` row with that reason |
| 1:50 | The agent declares an intent | `keyorix agent intent declare --secret prod/db-password --purpose deploy --max-uses 1` | intent id 812, plus the audit row id and `entry_hash` as a receipt |
| 2:20 | The agent reads under the intent | `keyorix secret get prod/db-password --intent 812` | the value; a `secret.read` row bound to intent 812 |
| 2:40 | A second read is refused | same command again | `403 agent_intent_exhausted` |
| 3:00 | The agent reports | `keyorix agent intent outcome 812 --status success` | an `agent.outcome` row; the intent is closed |
| 3:20 | A second intent is left without an outcome (agent killed); fast-forward the sweeper | `keyorix agent intent declare … --not-after 10s`, read, `kill`; `keyorix-server admin sweep-agent-intents --now` (a demo-only trigger) | an `agent.outcome_missing` row with `reads_used: 1` |
| 3:50 | Export for an auditor, with a nonce | `keyorix agent-ledger export --session 9 --nonce demo-2026 -o bundle.json` | `bundle.json`; an `agent_ledger.exported` row |
| 4:10 | Verify offline: no server, no DB | `keyorix-server admin verify-audit --agent-bundle bundle.json --checkpoint-key-file ck.key --expect-nonce demo-2026` | `VERIFIED`; findings: 1 missing outcome (intent 813); coverage (head id, time, anchor); the "does not prove" lines |
| 4:35 | Tamper and re-verify | change one byte of intent 812's `purpose` in `bundle.json`, run the same command | `BROKEN: record 1043 entry_hash does not re-derive` |

Fallback without a TSA or a key: the verdict is `NOT_PROVEN`. Say why: the
head is not authenticated. That is the honest result, not a failure of the
demo.

## 7. Implementation plan (next sessions), one commit per step

Rules for the split:

- each PR stands alone and stays under about 400 changed lines excluding
  tests;
- hot files (`openapi.yaml`, `server/main.go`, middleware token routing) are
  edited in the last commit of their PR;
- ADR-118 must be Accepted before PR A starts (Andrei approved implementing
  from Proposed on 2026-10-23; the status change is separate from that
  approval);
- all decisions D1-D8 are answered (ADR-118, "Decisions (Andrei,
  2026-10-23)"), so no `adrOpenDecisionRegistry` entry is needed for them.

**PR A — core and storage** (`internal/core`, `internal/storage`; the strict
per-transaction intent commit of D2 waits for OPT-AUDIT-RT-1 to free the audit
write path. Until it lands, intents inherit the global `audit_durability`, the
MVP does not fully guarantee strict intents, and the agent-ledger posture and
status output must say so explicitly):

1. Models and migrations: `agent_sessions` and `agent_intents`;
   `identity_type = agent`; the permission `agents.delegate`. Tests: migration
   up/down on SQLite and PostgreSQL.
2. Session start/end/revoke in core: the delegation ceiling (actor-derived),
   fail-closed start, owed end/revoke, `seq` allocation under the session
   lock. Tests: the ceiling matrix (delegator lacks, agent lacks, global
   admin, impersonation refused); owed end under audit refusal.
3. Intent declare: `withAuditedMutation`, the `kx-agent-v1` builder, scope
   re-derivation at each intent. Tests: fail closed on audit refusal; a
   narrowed delegator narrows the intent.
4. Release gate in the core value-read entry points: intent lock, target
   check, `uses_left` decremented in the read's audit transaction, the four
   denial reasons. Tests: concurrent reads never exceed `max_uses` (the
   `TestMaxReads_*` shape, on PostgreSQL across replicas); no release when the
   intent row is not committed (fault injection); every value route carries
   the gate (a registry test like `TestValueReadRoutes_AuditTheirRefusals`).
5. Outcome through `commitOwingAudit`; the sweeper (scheduler lock); late
   outcomes. Tests: audit refused → owed → backfilled exactly once; sweeper on
   two replicas writes one row; a faultops registry entry for each new owing
   op.
6. `INVARIANTS.d` fragments: INV-CORE-agent-release-needs-committed-intent,
   INV-CORE-agent-intent-terminal-owed, INV-CORE-agent-scope-actor-ceiling.

**PR B — transports** (`server/http`, `server/grpc`, `server/middleware`):

1. HTTP handlers and gRPC methods (parity, ADR-105). Real-server journey.
2. `kx_agent_` credential routing in `validateToken` and the gRPC
   interceptor. Coordinate with OPT-READPATH-2 or follow it.
3. `openapi.yaml` and proto: last commit.

**PR C — export and offline verify** (`internal/auditverify/agentbundle`,
`server/admin`, export handler):

1. `kx-agent-v1` strict parser in the verifier package (a leaf; no core or
   storage imports). Fuzz target on the parser; differential test against the
   writer's builder over shared fixtures.
2. Bundle builder (segment mode) and `GET /agent-ledger/export` with the
   fail-closed export row and the nonce.
3. `verify-audit --agent-bundle`: checks 1–5 of ADR-118 §5, verdict ranks,
   the "does not prove" output. Tamper tests in the
   `TestExhaustiveByteTamper_*` style for every ledger field.

**PR D — tree heads (D4: segment mode ships first, tree heads are their own PR
and land before a third-party auditor relies on the export):** the scheduler computes tree heads after
a chain verification, stores the left frontier at purges, and serves
inclusion and consistency proofs. RFC 9162 test vectors.

**PR E — clients:** CLI commands (after CLI-UX-2); `keyorix-mcp` declares an
intent and reports an outcome per `keyorix_get_secret` call (MCP is the first
real agent); operator guide; `docs/demo/agent-ledger.md` from §6 (coordinate
with DEMO-LOCAL-2).

**PR F — formal:** the model changes and configurations from §4. They go
first if possible: a seeded-bug verdict table before the code is the cheapest
review.

**PR G — threat model:** each AGL row switches from GAP to its new test.

## 8. One-page brief (for the memoria técnica; public-repo content only)

**Agent evidence ledger: tamper-evident, pre-execution records of AI-agent
credential use**

*Problem.* AI agents now fetch credentials from secret stores to act on
production systems. Existing secret-store audit logs record that a value was
read. They do not record who the agent was acting for, what it said it would
do before it got the value, or what happened afterwards. They also offer no
proof that a third party can check. Agent-logging proposals, such as the
IETF individual draft `draft-sharif-agent-audit-trail`, have the agent record
its own actions, and a self-written record proves only what the agent chose
to write.

*Approach.* Keyorix holds the credential, so it can enforce the record:

- **Delegated agent sessions.** A person or service starts an agent run with a
  scope no wider than its own authority. The scope is re-checked at every
  step.
- **Intent before release.** The agent declares purpose and targets. Keyorix
  writes that intent into its hash-chained audit log, and releases no value
  until the intent is durably committed. Each release is bound to its intent.
- **Outcome after, never lost.** The agent's outcome is recorded. If the agent
  goes silent, Keyorix records that, so "no outcome" is a fact in the log,
  not a gap. These post-event records use Keyorix's owed-audit mechanism, whose
  no-loss and no-block properties are machine-checked with a TLA+ model.
- **Offline verification.** An export bundle carries the records, hash-chain
  or Merkle proofs and external anchors (RFC 3161). An auditor verifies it
  without the server or database, and the report states what it does not
  prove.

*What is new.* The pre-execution record is enforced by the secret-holding
authority, not self-reported. A missing outcome has a defined, recorded
meaning, with formally checked semantics. The ledger reuses the existing
audit chain without changing its encoding, so existing verification keeps
working. (A search claim, not a proof: we have not found this combination
published.)

*Status (2026-10-23).* Design and ADR proposed (ADR-118), threat model and
formal-model plan written, record format checked with a throwaway prototype
against the existing verifier. Implementation is planned in seven reviewable
steps.

*Relevance.* It provides evidence for logging duties for AI systems, such as
EU AI Act Art. 12 record-keeping (mapping in §2; every external claim is
marked for verification), and ICT logging in financial services (DORA). It is
an accountability record, not a behaviour record: it cannot prove what an
agent did with a credential after release, and says so.
