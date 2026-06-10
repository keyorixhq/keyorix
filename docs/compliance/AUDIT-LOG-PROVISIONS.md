# Keyorix Audit-Log & Record-Keeping Provisions

This document describes exactly **what Keyorix logs, how, and how it maps onto
the audit-log / record-keeping expectations** of NIS2 and DORA. It is the
companion to the broader [controls statement](./NIS2-DORA-ISO-CONTROLS.md).

> See [`README.md`](./README.md) for the positioning disclaimer. This is an
> informational mapping of shipped capabilities, not a certification or legal
> advice. Article numbers are for orientation; confirm applicability with counsel.

## Why this matters

Both NIS2 (Art. 21(2), in support of incident detection and handling) and DORA
(ICT-activity detection and record-keeping) expect regulated entities to keep
durable, attributable records of who did what to sensitive systems, and to be
able to surface those records during an incident or an audit. Because Keyorix is
self-hosted, **you** own and retain those records — Keyorix's job is to produce
them completely, attributably, and without leaking the secrets they describe.

---

## 1. What is logged

Every security-relevant event is written to the audit trail:

| Category | Events |
|---|---|
| Secret lifecycle | create, read, update (with metadata diff), delete |
| Sharing | share create, modify, revoke (incl. group shares) |
| Authentication | login success, login failure, logout, session refresh |
| Authorisation / RBAC | role assigned/removed (user & group), permission assigned/removed to role |
| Membership | each membership state transition (invited → … → active, revoked) |
| Invitations & access requests | invitation sent/accepted/revoked/expired; access request created/approved/rejected/withdrawn |
| Account lifecycle | suspend, reactivate, force-password-reset, credential displayed out-of-band |
| Machine identities | create, activate, suspend, revoke, migrated-from-user |
| Impersonation | `impersonation.start` / `impersonation.end` (with duration + action count) |

## 2. What each record contains

Each audit event carries, at minimum:

- **Actor identity** — the acting user or principal.
- **`actor_type`** — `user`, `machine_identity`, or `system`, so machine and
  human activity are distinguishable.
- **Timestamp** — server-side, on every row.
- **Action / event type** and **target** (e.g. secret by id/name, role, project).
- **Outcome** — success/failure (failed authentications are recorded).
- **Delegation attribution** — `impersonated_by` / `acting_as` (resolved to
  human-readable usernames) whenever the action occurred under an impersonation
  session; the `impersonation` flag is set on **every** action in that session.
- **Change diff** — for `secret.updated`, a before/after diff of non-sensitive
  metadata (max_reads, expiration) plus a `{"value":{"changed":true}}` marker.

## 3. The no-leakage guarantee

Audit records reference secrets **by id/name only**. They never contain:

- plaintext secret values,
- passphrases or DEK/KEK key bytes,
- raw authentication tokens (tokens are SHA-256 hashed before use; API keys are
  masked).

This is enforced and regression-tested (leak-assertion tests on the diff path),
so audit logs can be forwarded to a SIEM or shared with auditors without
exposing the secrets they describe.

## 4. How records are accessed, exported, and forwarded

- **Query / filter** — the audit API supports filtering by event type(s), actor,
  project, `actor_type`, time window, and success/failure.
- **Pull export** — cursor-paginated `GET /api/v1/audit/export` for bulk
  retrieval into your own systems.
- **Push (SIEM)** — async, best-effort, bounded-queue connectors for **Splunk
  HEC**, **Datadog**, and a **generic webhook**, wired through a single emission
  funnel so all event families are forwarded consistently. No plaintext is ever
  forwarded (the value diff is a marker only).
- **Live tail** — a server-streaming gRPC `StreamAuditLogs` (when the gRPC
  surface is enabled) tails events after stream open, honouring the same filters.

## 5. Retention

- Audit history is stored in **your** PostgreSQL. Keyorix imposes **no retention
  cap and no retention paywall** — retain logs for as long as your policy
  requires (NIS2-grade durable record-keeping is a configuration of *your*
  database lifecycle, not a Keyorix limit).
- Standard PostgreSQL backup/restore applies; the [self-hosting
  runbook](../SELF_HOSTING.md) documents it.

---

## DORA-oriented audit-log checklist

A practical checklist a financial entity can walk through with its auditor. Each
row states the expectation and the Keyorix capability that addresses it.
(Article references are for orientation; confirm exact applicability with counsel.)

| # | Expectation | Keyorix capability | Status |
|---|---|---|---|
| 1 | Access to ICT assets is logged with attributable identity | Every event carries actor identity + `actor_type` | ✅ |
| 2 | Privileged / delegated actions are distinguishable | `impersonated_by` / `acting_as` + per-session impersonation flag | ✅ |
| 3 | Authentication events (incl. failures) are recorded | login success/failure, logout, refresh logged | ✅ |
| 4 | Changes to authorisation are recorded | RBAC role/permission/group changes audited (HTTP + gRPC routed through the audited choke point) | ✅ |
| 5 | Cryptographic key operations are recorded | DEK rotation audited; key files in perm checks/audit | ✅ |
| 6 | Records do not expose the protected data | No plaintext/keys/tokens in logs (regression-tested) | ✅ |
| 7 | Records are exportable for examination | Cursor-paginated pull export | ✅ |
| 8 | Records can be forwarded to monitoring/SIEM | Splunk HEC / Datadog / webhook push connectors | ✅ (operator-configured) |
| 9 | Records are retained for the required period | Operator-owned PostgreSQL, no cap | ✅ (operator-controlled) |
| 10 | Records support incident detection | Built-in anomaly alerts + filterable/streamable audit query | ✅ |
| 11 | Tamper resistance of records | Append-style writes in operator-controlled DB; **WORM/cryptographic chaining is Roadmap** | ⚠️ Roadmap |

> **Honest gap:** Keyorix does not yet provide cryptographic chaining /
> write-once-read-many tamper-evidence on the audit table itself; integrity today
> relies on operator-controlled PostgreSQL and standard DB controls. This is a
> tracked roadmap item — do not represent it as shipped.
