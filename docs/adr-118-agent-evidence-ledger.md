# ADR-118: Agent evidence ledger (intent before release, outcome after, offline-verifiable export)

**Status:** Proposed (2026-10-23). Andrei answered all open decisions D1-D8 on
2026-10-23 and approved implementing from this Proposed status; the answers and
their binding conditions are in "Decisions (Andrei, 2026-10-23)" at the end.
The ADR is not marked Accepted here (the implementation plan requires Accepted
before PR A starts). It was numbered ADR-116 in its first draft and is
ADR-118 from the number allocation of 2026-10-23: 116 = signed audit
checkpoints (#3665), 117 = TPM-sealed KEK (#3667), 118 = this ADR (#3668),
119 = attestation-gated secret release (#3666), 120 = attenuating agent tokens
(#3669).
**Date:** 2026-10-23
**Context:** R&D item R6 (agent evidence ledger MVP). Builds on ADR-029 (hash
chain), ADR-030 (machine identities), ADR-061 (`keyorix-mcp`), ADR-112
Amendments 3, 4 and 6 (audit durability, skipped reads, owed audit rows) and
the owed-audit TLA+ model (`docs/design-rd-tla-owed-audit.md`, #3647).
Related drafts (all Proposed): ADR-116 signed audit checkpoints (#3665) can
anchor the ledger's tree heads and exports; ADR-120 attenuating agent tokens
(#3669) is the credential an agent session could present.
Design detail, field mapping, TLA+ extension plan, demo and implementation
plan: `docs/design-rd-agent-ledger.md`. Threat rows:
`docs/security/threat-models/agent-evidence-ledger.md`.

## Context

AI agents (an IDE assistant, an automation run, `keyorix-mcp` driven by a
model) now fetch secrets from Keyorix. Today such an agent is an ordinary
machine identity. Its reads are audited like any read: one `secret.read` row,
written and committed before the value is returned (audit-before-disclosure).
That row records *that* a value was released. It does not record:

- **who the agent was acting for.** The person or service that started the run
  is not in the row, so no delegation is recorded;
- **what the agent said it would do before the release.** No declared purpose,
  task reference or scope exists that the release was checked against;
- **what happened afterwards.** No record shows whether the task succeeded,
  failed, or was never reported because the agent died;
- **a portable proof.** No export lets a third party check these records
  without access to the Keyorix server or its database.

Regulators and standards bodies are converging on exactly this record:
traceable logging for AI systems (EU AI Act Art. 12 [VERIFY: read on a
secondary site, artificialintelligenceact.eu, not the Official Journal]), ICT
logging under DORA [VERIFY], and two logging standards in draft (prEN 18229-1,
ISO/IEC DIS 24970 [VERIFY: neither text read; both are paywalled]). An
individual IETF draft, `draft-sharif-agent-audit-trail` (read in this session at
-08, 2026-10-13), defines a `pre_execution` record phase: "The record exists
BEFORE the action runs."
Its records are written by the agent's own recorder. A record that the agent
writes about itself proves only what the agent chose to write.

Keyorix holds the secret, so it is in a stronger position. It can refuse to
release a value until a pre-execution record exists and is durable at an
authority the agent does not control. This ADR decides how.

### Constraints this ADR must keep

- **Audit-before-disclosure** stays exactly as it is. No secret value leaves
  the server before its audit record is durable (ADR-112, Amendment 3 for what
  "durable" means at each level).
- **The audit write path is not changed.** No new hashed column, no change to
  the entry-hash encoding, no change to `internal/storage/store`'s audit writer
  or the flusher. The offline verifier (`internal/auditverify`) keeps
  verifying every existing row unchanged.
- **Revocations are never blocked by the audit log; widenings fail closed**
  (ADR-112 Amendment 6, INV-CORE-revocation-audit-owed,
  INV-CORE-security-mutation-audit-same-tx).
- **No secret value, ever, in any ledger record or export.**
- **A machine is never a global admin** (ADR-030). An agent is no exception.

## Decision

### 1. Agent identity: a machine identity of type `agent`, plus a delegated agent session

**Decided: a flavour of machine identity, not a new principal kind.** An agent
is a `machine_identities` row with `identity_type = agent` (the column already
holds `ci | k8s | service | automation | other`). It has project-scoped roles
through `machine_identity_roles`, no admin bypass, and instant cut-off when it
is suspended or revoked. All of this is unchanged ADR-030 behaviour.

The new object is the **agent session**: one run of an agent, started by a
delegator.

| Field | Meaning |
|---|---|
| `id` | session id (also the correlation key in every ledger record) |
| `machine_identity_id` | the agent identity (type `agent`, state `active`) |
| `project_id` | the agent identity's project; a session never spans projects |
| `delegator_type`, `delegator_id` | `user` or `machine_identity` that started the run |
| `scope` | the permissions and secret targets (ids or path globs, environments) delegated to this run |
| `expires_at` | at most `agent_ledger.max_session_ttl` (default 1 h, cap 8 h) |
| `max_intents` | optional bound on intents per session |
| `task_ref` | an opaque external reference (ticket, pipeline run id), at most 128 bytes, never free text |
| `state` | `active`, `ended`, `revoked` |
| `next_seq` | the next per-session record sequence number (section 4) |

**Starting a session is a widening.** The delegator calls
`POST /api/v1/agent-sessions` with its own credential. The server checks the
following, and writes the `agent.session_started` audit row in the same
transaction as the session row (fail closed, like any grant):

- the delegator holds `agents.delegate` on the project (a new permission,
  included in project-admin roles only by default);
- the requested scope is within the agent identity's own roles AND within the
  delegator's own effective permissions at that moment. The ceiling is derived
  from the actor, not picked from the target (CLAUDE.md, "a ceiling that
  inspects only the target is not a ceiling");
- the agent identity is `active` and of type `agent`.

The response carries a **session credential** `kx_agent_<base64url(32 bytes)>`,
shown once and stored hashed. It works only for that session, only until
`expires_at`, and only while the agent identity, the delegator and the session
are all still active. The agent identity's long-lived machine tokens (ADR-030)
cannot read a secret through the ledger gate (section 3). They can be issued
for an `agent` identity only if the operator turns on
`agent_ledger.allow_static_tokens` (default false).

**Authority is re-derived at every intent**, not frozen at session start:
effective = roles(agent identity) ∩ permissions(delegator, now) ∩ session
scope. If the delegator loses a permission or is suspended, the session
narrows or dies on its next intent. Ending or revoking a session is a narrowing
and uses the owed path (section 3).

**Why not a new principal kind (`actor_type = agent`).** A new kind adds a
third branch to `AuthorizePrincipal`, a third ID space (the class of bug
ADR-092 fixed), and a new value in a hashed column that every audit consumer
(filters, billing machine-read counts, access reviews, the SIEM export,
`AuditActorKindWhere`) would have to learn. An agent's authority is a machine's
authority, narrowed by a delegation. The flavour-plus-session model represents
exactly that, and it reuses every machine control that is already tested.
What the flavour loses is a hashed `actor_type` that says "agent". Section 4
puts the agent attribution into the hashed `diff` instead, so the chain still
covers it.

### 2. The INTENT record: written and durable before any release

Before it uses a secret, the agent declares an intent:
`POST /api/v1/agent-sessions/{id}/intents`, authenticated with the session
credential. The body holds:

- the targets: one or more secret ids or refs, each of which must be inside the
  session scope;
- a `purpose_code` from an operator-defined list (`deploy`, `rotate`,
  `incident`, `test`, ...);
- an optional `tool` label;
- `max_uses` (default 1);
- `not_after` (default 5 min, never beyond the session's `expires_at`);
- optional agent-asserted metadata (`agent_version`, `model_id`,
  `input_digest`).

The server writes an `agent_intents` row (`open`, `uses_left = max_uses`) and
the `agent.intent` audit row **in one transaction, through the existing
audited-mutation writer** (`withAuditedMutation`). If the audit append fails,
nothing commits and the agent gets 503. An intent widens what the agent can
do, so it fails closed, exactly like a grant
(INV-CORE-security-mutation-audit-same-tx). The response returns the intent id
and the audit row's id and `entry_hash`, which give the agent a receipt it can
log on its own side.

**Release gate (audit-before-disclosure, extended).** A value read with a
session credential must carry `X-Keyorix-Agent-Intent: <id>` (gRPC metadata
`keyorix-agent-intent`). Before the existing read path runs, the server
checks, under a row lock on the intent:

- the intent exists and belongs to this session;
- the intent is `open` and `now < not_after`;
- the secret is one of the intent's targets;
- `uses_left > 0`. The counter is decremented in the same transaction as the
  read's own audit row, so the counter and the row cannot disagree.

Any failure refuses the read and writes a denied `secret.read` row with a new
reason class (`agent_intent_required`, `agent_intent_closed`,
`agent_intent_target`, `agent_intent_exhausted`). This uses the existing,
aggregated denial machinery (ADR-112 Amendment 4, #3273).

On success, the normal `secret.read` row is written and committed before the
value is returned, as today. Its `diff` carries `{"agent_intent": <id>,
"agent_seq": <n>}`, so each release is bound in the chain to its intent.

So no value is released unless the intent row was committed **in an earlier
transaction**, and the read row was committed **before the response**. The
intent row is durable at the deployment's `audit_durability` level. Decision D2
(Decisions section) commits intent rows at `strict` even on a `standard`
install once the store has a per-transaction durability override. **Until it
does, intents inherit the global `audit_durability`, so the MVP does not fully
guarantee strict intents**, and the posture and status output says so.

**Skipped reads.** `insecure_audit_skip_reads` (ADR-112 Amendment 4) can still
skip the per-read row. The intent row and its terminal row are not reads, so
they are never skipped. The terminal row also carries the server's own count
of values released under the intent (`reads_used`, taken from the intent's
counter), so the ledger keeps the number of releases even when the per-read
rows are skipped. This ADR does not change Amendment 4's skip set.

### 3. The OUTCOME record: written after, owed when the audit log is down; what a missing outcome means

After the task, the agent reports:
`POST /api/v1/agent-intents/{id}/outcome` with:

- `status`: `success | failure | partial | abandoned`;
- `error_class`, optional;
- `output_digest`, optional;
- `started_at` / `finished_at` as the agent asserts them;
- a free-text summary, only if text recording is on (section 6).

The server closes the intent (`state = closed`, `uses_left = 0`) and writes
`agent.outcome` **through the owed path** (`commitOwingAudit`): the close and a
`pending_audit_events` record of the row commit in one transaction, then the
row is appended and the record claimed in one transaction. If the audit log is
refusing writes, the outcome is still accepted (202). It stays durable in the
owed ledger and is backfilled exactly once, in owed order, keeping its
original event time (ADR-112 Amendment 6). The reasoning matches revocations:
the outcome closes the intent, which narrows, and it describes an effect that
has already happened. Refusing it during an outage would lose the record when
the agent exits.

**A missing outcome is a recorded fact, never a silent absence.** Every intent
is owed a terminal record. A server sweeper (scheduler lock, single flight
across replicas) finds intents still `open` at `not_after + grace` (default
grace 5 min). It sets them to `missing` and writes `agent.outcome_missing`
(actor `system`), also through the owed path. The row states:

- the server released `reads_used` values under this intent;
- the agent did not report what it did with them before the deadline.

It is an evidence gap to be followed up, not proof of misuse. The verify report
lists every such intent, and a counter (`keyorix_agent_outcome_missing_total`)
and an optional notification make it visible. A revoked or ended session
closes its open intents the same way, with `reason = session_ended`.

A late outcome (after `missing`) is still accepted and recorded as
`agent.outcome` with `late = true`. It never replaces or hides the missing
row.

**An outcome without an intent** cannot be recorded through the API (unknown
or foreign intent: 404, and a denied `agent.outcome` row with `success=false`
through the existing best-effort denial path). An outcome row in the chain
whose intent is not earlier in the chain is a verifier finding (BROKEN in
segment mode, section 5).

**Inherited gaps.** The owed path has the gaps the TLA+ model confirmed: a
second, independent fault in the pending table loses the row loudly, and that
fault plus a crash at the wrong moment loses it silently
(`docs/design-rd-tla-owed-audit.md`, "Known gaps"; the fix is in review as
#3656). The ledger inherits these gaps and inherits that fix. It adds none of
its own: the sweeper turns any intent left without a terminal row into a
recorded `outcome_missing`, unless the same double fault also hits the
sweeper's own row.

### 4. Record fields, and how the records enter the hash chain unchanged

The ledger adds **audit event types**, not columns. The new types are:

- `agent.session_started`
- `agent.session_ended`
- `agent.intent`
- `agent.outcome`
- `agent.outcome_missing`
- `agent_ledger.exported`

`secret.read` gains the `diff` keys from section 2.

Every row is built by the existing `emitAudit*` / `withAuditedMutation` /
`commitOwingAudit` writers, so every row goes through the existing chain
encoding. The 13 hashed fields (`internal/auditverify/hash.go`) are filled like
this:

| Hashed field | Ledger use |
|---|---|
| `event_type` | the new types above |
| `user_id` | nil for agent-actored rows (a machine caller, ADR-092); the delegator's id on `agent.session_started` when the delegator is a user |
| `secret_node_id` | set when an intent has exactly one target, and on `secret.read`; else nil |
| `project_id` | the session's project |
| `ip_address` | the caller's address, as on every row |
| `description` | a short sanitized sentence for humans (`agent "deploy-bot" declared intent 812 (deploy) on 1 secret`) |
| `success` | false only on denial rows |
| `event_time` | server time; an owed row keeps its original time (Amendment 6) |
| `diff` | the canonical ledger record below |
| `impersonated_by`, `acting_as`, `impersonation` | unset: an agent session cannot be started inside an impersonation session (refused, like machine token issuance today) |
| `actor_type` | `machine_identity` for agent-actored rows, `user` or `machine_identity` for the delegator's rows, `system` for the sweeper |

`MachineIdentityID` is **not** one of the hashed fields. The original encoder
omits it, and the verifier must duplicate that omission. A ledger that relied
on it would have an unhashed actor. So the ledger record in `diff` repeats
every attribution field, and the chain covers all of them.

**The `diff` record** (schema `kx-agent-v1`) is a JSON object with sorted keys,
no insignificant whitespace, integers as JSON numbers and strings as UTF-8. It
is written once by the server and never re-serialised: the verifier parses the
stored bytes and never re-encodes them. The fields are:

| Key | In | Meaning |
|---|---|---|
| `v` | all | `1` |
| `kind` | all | `session_started`, `session_ended`, `intent`, `outcome`, `outcome_missing`, `read`, `exported` |
| `session` | all but `exported` | agent session id |
| `seq` | all but `exported` | per-session sequence number, from 1, with no gaps, assigned under the session row lock and only to a row that will be written. A `secret.read` row skipped under `insecure_audit_skip_reads` takes no `seq`. An owed row reaches the chain late, so the seq values of a session form the set 1..n; they are not in chain order |
| `agent` | all but `exported` | `{"mi": <machine identity id>, "name": <name at the time>}` |
| `delegator` | `session_started`, `intent` | `{"type": "user"\|"machine_identity", "id": <id>}` |
| `scope_digest` | `session_started`, `intent` | SHA-256 of the canonical scope; `session_started` also carries the scope itself |
| `intent` | `intent`, `read`, `outcome`, `outcome_missing` | intent id |
| `targets` | `intent` | `[{"secret": <id>, "ref": <path at the time>}]` |
| `purpose` | `intent` | `purpose_code`; `purpose_text` only when text recording is on |
| `max_uses`, `not_after` | `intent` | the declared bounds |
| `agent_meta` | `intent` | agent-asserted `agent_version`, `model_id`, `input_digest`, `tool`; marked as asserted |
| `status`, `error_class`, `output_digest`, `late` | `outcome` | the agent's report |
| `reads_used` | `outcome`, `outcome_missing` | server-counted releases under the intent |
| `reason` | `outcome_missing`, `session_ended` | `deadline`, `session_ended`, `session_revoked`, `delegator_inactive` |
| `last_seq` | `session_ended` | the session's final sequence number, so omissions can be detected |
| `bundle` | `exported` | the bundle id, the caller's nonce, the selection and the head id the bundle covers |

Nothing in this table can hold a secret value. The value never passes through
the ledger code.

### 5. Export bundle and offline verify

**Export.** `GET /api/v1/agent-ledger/export` is gated by `audit.read` and
`system.read` (the same gate as `/audit/export`). It selects by session ids,
by time range, or by project, and takes a caller-chosen `nonce`. The export
first writes its own `agent_ledger.exported` row through the audited path,
fail closed: an export discloses audit data, so it is recorded before it is
returned. That row carries the nonce. It then builds a bundle whose head is at
or after that row. The bundle (`kx-agent-evidence-v1`, one JSON file) holds:

1. **Header:** format version, bundle id, creation time, selection, nonce, the
   chain encoding(s) present, and the server version. All of these are claims
   by the server, except where a record in the chain repeats them.
2. **Records:** the raw rows, all 13 hashed fields plus `id`, `prev_hash` and
   `entry_hash`, for:
   - every ledger row in the selection;
   - every agent-bound `secret.read` row;
   - the export's own row;
   - the latest ADR-112 settings-diff rows at or before the selection's start,
     so the bundle shows whether skipped reads or a durability level applied.
3. **Proof**, in one of two modes:
   - **segment**: every row from the first selected record to the head, in
     full. It works on today's chain with no new server component. It is
     complete by construction: the verifier sees every row in the range, so it
     can prove no ledger row was left out. It also discloses every unrelated
     row in the range (IP addresses, descriptions). Use it only when the
     recipient may see the whole audit log.
   - **tree**: an inclusion proof per record, against a signed **tree head**.
     The tree is an RFC 9162-style Merkle tree (leaf `0x00‖entry_hash`, node
     `0x01‖left‖right`) over the `entry_hash` of rows 1..N in id order. The
     checkpoint scheduler computes tree heads from rows that are already
     written, after it has verified the chain, so the audit write path does
     not change. Tree heads also give **consistency proofs**: an auditor who
     kept an earlier bundle can check that the log only grew between the two
     exports. Unrelated rows are revealed only as hashes. Completeness inside
     a session is shown by `seq` running 1..`last_seq` with no gaps (section
     4). An open session, which has no `last_seq` yet, is reported as
     INDETERMINATE for completeness.
4. **Anchors:** the checkpoint(s) or tree head(s) covering the head (HMAC
   signature, key version), their RFC 3161 token if the deployment has a TSA,
   and the number of owed rows still pending at export time. The pending count
   is a server claim.

**Offline verify.**
`keyorix-server admin verify-audit --agent-bundle <file>`
`[--checkpoint-key-file] [--tsa-roots] [--anchor <earlier bundle or anchor>]`
`[--expect-nonce] [--json]`. It needs no database and no server. It lives in a
new package next to `internal/auditverify` and reuses that package's
independent hash code (`ComputeEntryHash`, both encodings). It keeps
INV-AUDITVERIFY-01: no import of `internal/core` or `internal/storage`. When
R8 builds its standalone `keyorix-verify` binary, that binary embeds the same
package. The checks, in order:

1. Every record's `entry_hash` re-derives from its fields and `prev_hash`.
2. Segment mode: the rows link without a break up to the head. Tree mode: each
   inclusion proof reaches the tree head, starting from the leaf **derived in
   check 1, never from the stored `entry_hash`**. The prototype showed that a
   tampered row keeps its stored hash, which still proves inclusion. With
   `--anchor`: the tree is consistent with the earlier head.
3. The head is authenticated by the checkpoint key and/or an RFC 3161 token
   checked against `--tsa-roots`. Otherwise the verdict is NOT_PROVEN, never
   VERIFIED (the `auditverify` verdict ranks, INV-AUDITVERIFY-05).
4. Ledger semantics, from the stored `diff` bytes under a strict schema:
   - every `read` and `outcome` refers to an intent earlier in chain order;
   - reads are within the intent's targets, before `not_after`, and no more
     than `max_uses`;
   - each closed intent has exactly one terminal row (`outcome` or
     `outcome_missing`), plus at most one later `late` outcome;
   - a session's `seq` values form the set 1..n, compared as a set and not
     in chain order, and n equals `last_seq` once the session has ended;
   - the delegator is recorded, and every intent falls inside its session's
     lifetime.
5. The export row is present and carries `--expect-nonce` if one is given.
   This is how a relying party knows the bundle was made for its own request
   and is not a replay.

The report states:

- the coverage (head id, head time, the anchors used);
- the findings (missing outcomes, late outcomes, intents still open, owed rows
  pending at export, which makes the verdict INDETERMINATE, as for unsettled
  break-glass);
- **what it does not prove**: anything the agent asserted (its outcome,
  `agent_meta`, digests); what the agent did with a value after release; and,
  against a host administrator who holds both the database and the checkpoint
  key, anything beyond the last external anchor (`design-b4` §2).

### 6. Retention and redaction

- **No secret values.** No ledger field can hold one, and no ledger code path
  ever sees one.
- **No prompt or model text by default.** `agent_ledger.record_text` (config
  file only, default `false`) is the only switch that stores free text
  (`purpose_text`, outcome summary, each at most 1 KiB, sanitized like
  descriptions). When it is on: an INFO line at every start, the ADR-112 §1
  settings-diff records each change, and `admin validate --posture` shows it.
  With it off, the agent can send only codes, ids and digests. The server
  refuses (400) a text field it would not store, so the agent cannot assume
  text was kept when it was not.
- **Digests are not anonymisation.** `input_digest` and `output_digest` are
  agent-supplied. A plain SHA-256 of a short or guessable text can be
  confirmed by guessing. The agent guide recommends a keyed digest (HMAC with
  a key the agent operator holds). The server stores what it gets and labels
  it as agent-asserted.
- **Retention.** Ledger rows are audit rows and follow the deployment's audit
  retention, with three additions:
  - (a) retention never purges an intent whose terminal row is still open or
    owed (the same rule as for unsettled break-glass);
  - (b) the default floor for ledger rows is 6 months (`agent_ledger.min_retention`),
    because the AI Act's deployer log-keeping duty is commonly cited as "at
    least six months" (Art. 26(6) [VERIFY: not read]);
  - (c) a purge that crosses a session leaves the retention anchor
    (ADR-029 / #3257) as the proof of the sanctioned gap, and the verifier
    reports that session as INDETERMINATE for completeness.
- **Erasure.** Chained rows cannot be edited. Personal data in ledger rows is
  ids, an IP address and, with text recording on, operator-allowed text. The
  same position as the rest of the audit log applies; the operator guide says
  so.

## Alternatives considered

| Alternative | Why not |
|---|---|
| New principal kind `actor_type = agent` | Third ID space and authorization branch, a new hashed value every consumer must learn, and no machine control reused. See section 1. |
| Fold the intent into the `secret.read` row | Then nothing is declared before the read, an unused or refused intent leaves no trace, one intent cannot cover several reads, and no deadline exists from which a missing outcome could be derived. |
| A separate agent hash chain or table | A second write path and a second verifier, and no provable order between the two chains. The brief and the constraints exclude changing the write path; adding a second one is worse. |
| Store records in the IETF draft's format (JCS-canonical, per-record ES256 / ML-DSA signature) | The draft is an individual -08 draft and still changing. Per-record signatures need an asymmetric server key that R8 has not delivered yet. A field-mapping export to the draft's shape is cheap later (design note, mapping table). |
| Agent-signed records only (client-side ledger) | Self-asserted: the party being audited writes its own record. Kept as a later addition: an agent-held key, or an attested runtime (ADR-119, attestation-gated secret release, #3666), can sign `agent_meta` and the outcome. |
| Outcome fail closed | An outage would then lose outcomes when agents exit, and an agent would retry for ever. The owed path keeps the record durable without blocking anything (seeded bug `outcome_fail_closed` in the TLA+ plan). |

## New vs state of the art

- **Self-reported vs authority-enforced pre-execution records.**
  `draft-sharif-agent-audit-trail` (-08) specifies `pre_execution` records and
  requires them for some actions in high-risk systems (its §4.3, read in this
  session), but the agent's own recorder writes them. Here the
  secret-holding authority writes the pre-execution record. The authority
  refuses the release until that record is durable and binds each release to
  it in a tamper-evident chain that the agent cannot write to. We have not
  found a secrets manager that does this. This is a search claim, not a proof.
- **Existing secrets-manager audit is post-hoc and purpose-free.** Vault and
  OpenBao audit devices log each request and response, with values HMAC'd.
  Cloud secret stores log each value fetch to their audit trail. None of them,
  as far as we know [VERIFY against current product docs], records a declared
  purpose that the release was checked against, or pairs a release with an
  outcome or a missing outcome.
- **Owed semantics for evidence.** The terminal record of every intent is an
  obligation the server tracks: written, owed in a durable ledger, or written
  as `missing` by the server. Its no-loss and no-block properties are the ones
  the owed-audit TLA+ model checks, extended in the design note. We know of no
  agent-logging design that states, let alone model-checks, what a missing
  outcome means.
- **Not new:** hash chains, Merkle inclusion and consistency proofs (RFC 9162,
  Certificate Transparency), RFC 3161 anchoring, delegation with attenuation.
  The new part is combining them at the point of secret release, with the
  owed-audit asymmetry.

## Technical risks

- **The agent can lie.** Outcomes, digests and `agent_meta` are assertions.
  The ledger proves what was declared, what was released, and when. It does
  not prove what the agent did with the value. The threat model states this
  as the main residual (AGL-5).
- **Intent granularity vs usefulness.** Agents that do not know their targets
  in advance will ask for wide globs, and the gate then proves little. To
  mitigate: target globs are bounded by the session scope, `max_uses` defaults
  to 1, and the verify report lists the declared targets beside the targets
  actually read.
- **Latency.** One extra durable audited write per intent, and one more
  intent-row lock per read. No numbers are claimed. A benchmark belongs to the
  implementation PR, not to repository docs.
- **Durability at `standard`.** At the PostgreSQL default, an OS crash can
  lose a tail of up to ~600 ms of audit rows, and an intent and its reads can
  be lost together after the value was released. Decision D2 commits intent
  rows at `strict` once the store has a per-transaction durability override
  (a file another session currently owns). Until then intents inherit the
  global `audit_durability`, so the MVP does not fully guarantee strict
  intents. See D2 below.
- **Independent verifier drift.** The `kx-agent-v1` parser exists twice, in the
  writer and in the verifier. A differential test over shared fixtures
  (INV-AUDITVERIFY-02's pattern) is part of the plan.
- **Tree heads and retention.** Inclusion proofs for rows near a purge
  boundary need the subtree hashes of the purged range. The tree code must
  store a compact range (the left frontier) at each purge, or tree mode stops
  working for those rows. This is an implementation risk; segment mode is
  unaffected.
- **Hot files and owned areas.** The design touches the token-prefix routing
  in middleware (OPT-READPATH-2), `openapi.yaml`, `server/main.go` (scheduler
  wiring) and `cli/` (CLI-UX-2). The implementation plan orders the commits so
  that each of these edits is small and comes last.
- **Moving standards.** Every external standard named here is a draft or
  recently adopted. The mapping is maintained as a table with `[VERIFY]`
  markers, not as compliance claims.

## Consequences

- Agents get a first-class, least-privilege run identity with recorded
  delegation, without a new principal kind.
- Every agent release is preceded by a durable, chained intent and followed by
  a chained outcome or a recorded missing outcome.
- An auditor can verify an export offline, with stated limits.
- `keyorix-mcp` becomes the first adopter: each `keyorix_get_secret` call can
  declare its intent and report its outcome by itself (implementation plan,
  PR E).
- Nothing changes for existing machine identities, PATs or users. The ledger
  applies only to sessions of `agent` identities.

## Decisions (Andrei, 2026-10-23)

Andrei answered D1-D8 on 2026-10-23 and approved every recommended option. The
ADR stays **Proposed**: he approved implementing from the Proposed status, and
the ADR process has not moved it to Accepted. Each answer below is binding on
the implementation.

- **D1 Identity: a machine identity of type `agent` plus a delegated session.**
  Not a new principal kind. Reason: a new kind adds a third authorization
  branch and ID space and a new hashed `actor_type` value that every audit
  consumer would have to learn. Condition: no new principal kind, and no new
  hashed audit column.
- **D2 Intent durability: strict for `agent.intent` rows once the store has a
  per-transaction durability override; inherit `audit_durability` until
  then.** Reason: at `standard` an OS crash can lose an intent and its reads
  together after the value was released. **Binding obligation:** until the
  store offers the per-transaction override, intents inherit the global
  `audit_durability`, and the MVP does not fully guarantee strict intents. The
  ADR, the posture and status output, and the operator guide must say this
  plainly, and the output must not describe intents as strictly durable while
  the override is missing. The override belongs to the store area owned by
  OPT-AUDIT-RT-1; this ADR does not edit the audit write path.
- **D3 Static tokens: no by default.** An `agent` identity holds no ADR-030
  long-lived tokens that bypass the intent gate
  (`agent_ledger.allow_static_tokens: false`); an agent is reached only through
  sessions. Reason: a static token would let an agent read with no declared
  intent.
- **D4 Proof mode: segment mode first, tree heads as their own PR.** Tree heads
  land before any third-party auditor relies on the export. Reason: segment
  mode needs no new server component. Known cost: it discloses every unrelated
  row in the range, so the operator guide says that.
- **D5 Text recording: a plain setting.** `agent_ledger.record_text` defaults
  to false, and turning it on produces an INFO line at every start, a settings
  diff row and a posture line. It is not an `insecure_` opt-out. Reason: it
  adds personal data or prompt-like text to the log but does not weaken a
  security control.
- **D6 Missing-outcome deadline: 5 minutes after `not_after`, configurable from
  1 to 60 minutes.** Not a fixed 15 minutes.
- **D7 Gating: the ledger is in the AGPL core.** Reason: it is part of the
  audit story, and the project rule is that security is never paywalled; gating
  evidence would weaken the secure-by-default baseline. No licence-gated check
  in the ledger code paths. (ADR-112 open question 5 remains the related
  licensing question for other features.)
- **D8 Trust level: not in the MVP.** Ledger rows carry no `trust_level` field.
  A level in the style of the IETF draft's L0-L4 may be derived only inside a
  future draft-shaped exporter. Reason: deriving a level from the credential
  kind and the server gate is a policy claim, and the draft is an individual
  -08 draft that is still changing. Condition: no stored `trust_level`.
