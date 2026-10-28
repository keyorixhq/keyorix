# Design: accepting a real audit-row loss (audit re-seal options)

Status: **option A decided** (Andrei, 2026-10-23, ask avs1-reseal-command-choice) and
implemented by AUDIT-ACCEPT-LOSS-1 as `keyorix-server admin audit accept-loss`, with C's anchor
binding as an optional input (`internal/core/audit_seal.go`, `audit_seal_accept.go`). The
status after an acceptance is `sealed`, never `VALID` (constraint 1 of
`docs/design/recovery-options.md` §2), rather than the `VALID` with an accepted-gaps list
sketched below. The text below is the proposal as decided. Area: ADR-029
(signed checkpoints), ADR-112 (loud, audited opt-outs), RECOVERY-DESIGN-1 item 4.

## Why this is needed now

Since AUDIT-VERIFY-STATE-1 the server no longer starts audit verification over from whatever
it finds. A verification state row that is deleted, garbled, signed under another key epoch,
claims rows that are gone, or was put back over a recorded break raises a sticky
**verification state discontinuity** (`internal/core/audit_verify_state.go`). The status is
`BROKEN`, `keyorix_audit_verify_state_discontinuity` and `keyorix_audit_verify_failure_recorded`
read 1, and the chain gets a `system.audit_verification_state_discontinuity` event. No
verification clears it. Checkpoints of new rows continue.

The same is true for a proven truncation (#3547): the write path refuses, and the failure
stays until a full verification passes, which it never will if rows really are gone.

That is the intended fail-closed behaviour, but it leaves an operator with a real, understood
loss (a disk failure restored from an older backup of `audit_events` only, a botched manual
cleanup, a KEK rotation done before key changes carried the state over) with no supported way
back to a `VALID` status. Today the only path is out-of-band SQL, which is exactly the
unaudited re-baseline this work removed.

The command must not become the laundering tool it replaces. Requirements:

1. **Who**: someone who holds the master passphrase (so the KEK-derived checkpoint key),
   not merely a database writer or an API token holder.
2. **What is recorded**: what was accepted (the discontinuity or failure: kind, detection
   time, reason, the claimed and the surviving head), who accepted it, when, and why (a
   ticket or free-text justification). Signed with the checkpoint key.
3. **Where it shows**: in the hash chain itself (an event after the gap), in the signed state
   (forever, not only until the next save), and in every verifier output: incremental status,
   `--full`, posture, the evidence pack, offline `admin verify-audit`.
4. **After**: verification resumes from a sealed baseline at the acceptance point; the
   accepted gap is reported as accepted, never silently dropped; a later row put back from
   before the acceptance is again a discontinuity.

## Options

### A. Offline key-holder command (`keyorix-server admin audit accept-loss`)

Runs on the server host with the server stopped, under the exclusive admin lock (like
`admin restore` and `recover-admin`), with the master passphrase from the usual sources.

- Reads the active discontinuity / sticky failure and shows it, with the surviving chain
  head, the last pinned head, and the latest checkpoint and high-water claims. Requires
  `--confirm` and `--reason "<text or ticket>"`; prints what it will write first.
- Writes, in one transaction:
  - an in-chain event `system.audit_loss_accepted` (actor: the OS user running the command
    plus the `--operator` name given; description: the accepted record and the reason);
  - a fresh checkpoint and high-water mark of the surviving chain (the re-seal);
  - the state row: the discontinuity/failure moves to a signed, append-only
    `accepted` list (`{accepted_at, gen, audit_event_id, kind, reason, operator,
    justification}`), the pin is reset to the new checkpoint, the rolling cycle restarts.
- Afterwards: status is `NOT PROVEN` until a full verification that started after the
  acceptance completes, then `VALID` with an `accepted_gaps` list in the report (and a
  `keyorix_audit_verify_accepted_gaps` gauge). The acceptance event counts as a recorded
  break for the "row put back from before a break" check.

Pros: matches the trust model exactly (the key, not the database, is the authority);
no new API surface; works for SQLite and PostgreSQL; one person can recover in an outage.
Cons: needs downtime; single person (no dual control); the operator must be on the host.

### B. Online dual-control API (`POST /api/v1/audit/verification/accept`)

A `system.write` endpoint with step-up MFA that creates a pending acceptance; a second
administrator approves it (the access-request approval machinery), then the server writes
the same records as in A while running.

Pros: no downtime; dual control; HA-friendly (the checkpoint lock already serialises it).
Cons: an API credential (two, with approval) becomes able to erase loss evidence: a weaker
authority than the KEK, and the exact capability an attacker who owns an admin account wants.
More surface (OpenAPI, CLI, web, gRPC per the contract rule). Needs ADR-112 treatment as an
audited weakening.

### C. Anchor-bound acceptance (A or B, plus external proof)

The command additionally takes the best external evidence available: an
`export-checkpoint` file, an RFC 3161 token, a backup, or the high-water witness file. It
verifies the surviving chain against it and records the exact lost range
(`ids (a, b]`, `n` events) instead of "continuity lost". Without such evidence it refuses
unless `--no-external-evidence` is given, which is itself recorded.

Pros: the record says precisely what was lost, which is what an auditor asks; discourages
accepting a loss nobody measured. Cons: evidence is often missing in exactly the cases that
need this; more operator steps.

## Recommendation

**A, with C's evidence binding as an optional input** (record the exact range when an anchor
or backup is supplied; record "unmeasured" plus the flag when not). It keeps the authority
where the cryptography already puts it (the KEK holder), adds no API surface an attacker with
an admin token could use, and its record is in the chain, in the signed state and in every
verifier. B can be added later if downtime proves to be the real cost, as a separate ADR-112
opt-out.

Separately, and independent of the choice: **make `rotate-kek` and `migrate-provider` carry
the verification state over** (they hold both keys: re-sign the state row, the latest
checkpoint and the high-water mark under the new key, and append a
`system.audit_key_epoch_changed` event). Until that lands, every honest key change produces
an `other key epoch` discontinuity that only this command can accept. This is
RECOVERY-DESIGN-1 item 4 and removes the most common false alarm.

## What this does not cover

- An actor who truncates the chain back past the
  `system.audit_verification_state_initialized` marker **and** deletes (not relabels) every
  checkpoint row, the high-water mark and the state row leaves a database indistinguishable
  from a deployment that never checkpointed. Only out-of-database evidence catches that: the
  high-water witness file, an external anchor, a backup.
- Deployments without the checkpoint scheduler (no incremental verification) keep no state
  row; their status is the full walk, as before.

## Draft ADR amendment (text only; not applied)

> **ADR-029 amendment (audit verification state continuity).** The signed verification
> state is part of the audit evidence. A state row that cannot be continued (deleted,
> malformed, failing its signature under the current key, claiming rows the chain no longer
> has, or saved before a break the chain records) is a sticky discontinuity, reported as a
> break, never a fresh start. An honest first start is recognised by the absence of every
> trace of earlier verification: no state row, no `system.audit_verification_state_initialized`
> marker in the chain, and no checkpoint or high-water mark that fails its signature. Only an
> audited key-holder action (`admin audit accept-loss`) may accept a discontinuity; it
> records the acceptance in the chain and in the signed state, and verifiers report accepted
> gaps for as long as the state exists. Key changes carry the state over under both keys.
