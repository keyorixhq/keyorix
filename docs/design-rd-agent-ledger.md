# Design note: agent evidence ledger

Status: R&D design (RD-AGENT-LEDGER-1), 2026-10-23. Docs only, **nothing here
is implemented**. The decision record is
[ADR-116](adr-116-agent-evidence-ledger.md) (Proposed). This note adds what an
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
| 12(1) automatic recording over the lifetime | server-written rows, not agent-written; chained; retention floor (ADR-116 §6) | supports the *secret-use* slice of an AI system's events only, not the model's own events |
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
| `trust_level` (L0–L4) | not stored | derivable: session credential + server-side gate. Assigning a level is a policy decision → NEEDS ANDREI D8 in the report |
| `parent_record_id` | `diff.intent` on read/outcome rows | |
| `prev_hash` | `prev_hash` | different canonicalisation: the draft hashes RFC 8785 JCS of the previous record; ours is the ADR-029 length-prefixed field encoding |
| `record_phase` | `agent.intent` = `pre_execution`; `secret.read` = `concurrent`; `agent.outcome` / `outcome_missing` = `post_execution` | the draft (§4.3) requires a `pre_execution` record before state-changing actions in high-risk systems; ours is enforced by the authority, not self-reported |
| optional `input_hash` / `output_hash` | `input_digest` / `output_digest` | the draft: SHA-256, "used instead of raw input to preserve privacy"; ADR-116 §6 recommends a keyed digest instead |
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
| retention and access control for logs | ADR-116 §6; export gated by `audit.read` + `system.read` |
| an information model / schema | `kx-agent-v1` (ADR-116 §4) |

### 2.5 DORA ICT logging (every row [VERIFY])

| Likely logging element [VERIFY] | Ledger field |
|---|---|
| logging of access to ICT assets and of privileged/credential use | `secret.read` bound to an intent; session and delegation rows |
| protection of logs against tampering and unauthorised access | hash chain, checkpoints, anchors, offline verify |
| retention of logs in line with the entity's policy | audit retention plus the ledger floor |
| clock synchronisation | server clock; RFC 3161 time on anchors |
| detection of anomalous activity | `outcome_missing`, denied reads, counters, notification |
