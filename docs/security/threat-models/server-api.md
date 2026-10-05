# Threat Model: Server API (REST + gRPC)

> Part of [`docs/security/threat-models/`](README.md). This is a
> per-component view derived from, and consistent with, the system-wide
> [`../threat-model.md`](../threat-model.md) (trust boundaries B3/B4) — it
> does not re-derive conclusions that document already reached, only
> narrows the focus to this one component with more operational detail
> and a dedicated data-flow diagram. Where the two ever disagree, treat
> that as a bug in this document and open an issue; `../threat-model.md`
> is the longer-standing, more-reviewed source.

## 1. System context

The server API is the single point every client goes through to reach
stored secrets and account data — there is no other path. As of this
writing: **343 files under `server/http/handlers/`** implementing the
REST surface, and **55 files under `server/grpc/services/`** implementing
a partial (data-plane-focused), 86-RPC subset of the same surface
([ADR-105](../../adr-105-grpc-scope-and-parity.md)). Every one of those
~400 implementation files reaches the same single authorization
chokepoint — this is the property the rest of this document is about.

```mermaid
flowchart LR
    subgraph Clients
        WEB[Web UI]
        CLI[CLI, remote mode]
        GRPC[gRPC clients /\nk8s delivery / SDKs]
        API3P[Third-party API clients]
    end

    subgraph Edge["server/middleware"]
        TLS[TLS termination]
        RL[Rate limiting /\nbody-size caps]
        SESS[Session / PAT / machine\ntoken validation]
        CSRF[CSRF double-submit\n(cookie clients only)]
    end

    subgraph Core["core.Authorize chokepoint"]
        AUTHZ[Scoped RBAC check\n(system/project/environment)]
    end

    subgraph Handlers
        HTTP[server/http/handlers\n(343 files)]
        GRPCSVC[server/grpc/services\n(55 files)]
    end

    DB[(Storage layer:\nSQLite / PostgreSQL)]
    AUDIT[(audit_events,\nhash-chained)]

    WEB --> TLS
    CLI --> TLS
    API3P --> TLS
    TLS --> RL --> SESS --> CSRF --> HTTP
    GRPC --> GRPCSVC
    HTTP --> AUTHZ
    GRPCSVC --> AUTHZ
    AUTHZ --> DB
    AUTHZ -. best-effort\nasync .-> AUDIT
    AUTHZ -. audit-before-disclosure\n(secret VALUE reads only) .-> AUDIT
```

## 2. Trust boundaries in scope

| Boundary (from `../threat-model.md` §3) | What crosses it here |
|---|---|
| B3 — REST API | Every human- and machine-facing HTTP request |
| B4 — gRPC API | The 86-RPC data-plane subset, same authorization chokepoint |

B1/B2 (CLI local vs. remote mode), B5 (web UI specifically), and B6 (k8s
delivery specifically) are covered in their own component documents —
this one covers what's common to every caller once a request lands at
the HTTP or gRPC edge.

## 3. STRIDE

- **Spoofing.** Tokens (session/PAT/machine) are 256-bit `crypto/rand`
  values, reusable ones SHA-256-hashed and looked up by hash, never
  compared in plaintext. See the [authentication](authentication.md)
  component doc for the full mechanism. *Residual*: a leaked raw token is
  valid until revoked/expired — mitigated by short session TTLs and an
  absolute lifetime ceiling refresh cannot extend.
- **Tampering.** Every write path funnels through
  `core.Authorize`/`core.AuthorizePrincipal` before mutation —
  `internal/core/authz.go`. PAT restrictions apply *before* role
  resolution and the admin bypass (ADR-042). *Residual*: none identified
  beyond ordinary authenticated-actor-does-authorized-thing (CLI local
  mode is the one structural exception — see
  [backup-restore.md](backup-restore.md)'s sibling note and
  `../threat-model.md` §4 B1/B2, §5.2).
- **Repudiation.** Every security-relevant action is audited with actor
  identity, `actor_type`, and outcome, including impersonation
  attribution — see [audit-chain.md](audit-chain.md).
- **Information disclosure.** Scoped RBAC limits read access at the same
  chokepoint as writes. **Open gap, tracked**: ~26 REST routes across 9
  handler files serialize raw, untagged `internal/storage/models` structs
  to JSON (`docs/findings/2026-09-25-FINDING-api-raw-model-exposure.md`)
  — mostly a PascalCase-vs-snake_case contract-hygiene defect, but two
  routes (`SearchAuditLogs`, `AccessHistory`) leak `IPAddress` (real PII)
  where a sibling route (`GetAuditLogs`, `AuditTrail`) already redacts
  it, proving the redaction was a deliberate design decision these two
  never received. Filed as
  [#2733](https://github.com/keyorixhq/keyorix/issues/2733)
  (`threat-model-gap`) — no tracking issue existed for this finding
  before this threat-model pass.
- **Denial of service.** Rate limiting, request-body size caps
  (`server/middleware.MaxBodyBytes` — see
  [`SECURE-CODING.md`](../SECURE-CODING.md) §9), pagination, bulk-op
  batch caps, and a bounded-BFS fix for `transitiveDependents` (matching
  its sibling `blastBFS`'s node/depth cap). *Residual*: none identified
  beyond ordinary capacity planning (`security-review-2026-09.md`
  "Availability and denial-of-service resistance").
- **Elevation of privilege.** Scoped RBAC (system/project/environment),
  least-privilege defaults (`system_viewer`), cross-project isolation
  enforced at every nested-resource route, gRPC authorized identically to
  HTTP — no flat-vs-scoped gap (`SECURITY-VERIFICATION.md` "Access
  control & authorisation" hardening log). The admin-bypass marker is a
  structural field (`models.Role.BypassesPermissionChecks`, ADR-084), not
  a name-matched role, closing a prior self-escalation-via-role-rename
  risk class. *Residual*: none identified after the cross-transport
  parity fix.

## 4. Residual risks specific to this component

- The information-disclosure gap above (#2733) is the one open item with
  a filed issue. Everything else in this section is carried forward from
  `../threat-model.md` §6 without re-litigation: the transient
  in-process secret-value exposure (heap copies between decryption and
  the wire) and the ~30s authentication cache window both apply to every
  request through this component and are not re-derived here.
