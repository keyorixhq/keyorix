# Threat Model: Connectors and Rotation Targets

> Part of [`docs/security/threat-models/`](README.md). Derived from
> [`../threat-model.md`](../threat-model.md) §4 (boundary B7) and
> [`../SECURE-CODING.md`](../SECURE-CODING.md) §10.
>
> **Naming note.** The task this document was written from referred to
> this component as "connector host (ADR-111, proposed)." Neither that
> ADR number nor a "connector host" concept — a dedicated, isolated
> execution environment for connector code, distinct from the main
> server process — exists anywhere in this repository as of this
> writing (confirmed by a repo-wide search). This document is named
> "Connectors" to describe what's actually shipped, and the absence of
> any process-level isolation is recorded as an open gap in §4 rather
> than described as if it already existed under a different name.

## 1. System context

Every outbound call to an external connector, KMS, or rotation target
(AWS/Azure/GCP SDKs, HashiCorp Vault, Postgres/MySQL rotation targets)
runs inside the main `keyorix-server` process — there is no separate
connector process or sandbox. Authorization scoping and SSRF guarding
happen at the call site, inside that same process.

```mermaid
flowchart LR
    REQ[Authenticated request\nreferencing a connector/\nrotation target]
    SCOPE["Tenant scoping check\n(scope, project, environment) +\nconnect.platform.use permission\n(terminal deny, no delegation — ADR-082)"]
    SSRF["SSRF guard\n(internal/netutil):\nlink-local/NAT64 address block"]
    REFVALID["rotation_ref denylist\nvalidation (config time)"]
    SDK["Third-party SDK call\n(AWS/Azure/GCP/Vault/\nPostgres/MySQL client)\n— same process, same privileges\nas secret-value handling code"]
    TARGET[(External connector /\nKMS / rotation target)]

    REQ --> SCOPE --> SSRF --> REFVALID --> SDK --> TARGET
```

## 2. Trust boundaries

| Boundary (from `../threat-model.md` §3) | What crosses it |
|---|---|
| B7 — Server ↔ external connectors/KMS/rotation targets | Outbound calls carrying operator-configured credentials |

## 3. STRIDE

- **Server-side request forgery (SSRF).** Link-local/NAT64 address
  guards on outbound connector/dynamic-secret calls
  (`internal/netutil`, `internal/core/dynamic_secrets_ssrf_test.go`,
  `internal/core/admin_dsn_ssrf_fuzz_test.go`) — an actively-fuzzed
  boundary (`FuzzAzureGenerateUpstreamRef`, `FuzzPostgresQuoting`,
  `FuzzMySQLQuoteString`). This is the exact class that already
  produced one real, shipped, fixed path-traversal vulnerability in
  `rotation_ref` handling, now additionally denylist-validated at
  configuration time.
- **Cross-tenant leakage via Connect.** Connectors are scoped to
  `(scope, project, environment)`, with ownership enforcement and
  `ListConnectors` filtering by the caller's authorized scope, plus a
  dedicated `connect.platform.use` permission gated as a **terminal
  deny** with no delegation fallback (ADR-082, all four implementation
  branches shipped). *Residual*: none identified after ADR-082's three
  rounds of revision — the ADR's own "Out of scope" section names what's
  deliberately deferred.
- **Signing-key MITM (OIDC/federation used by connectors).** Covered in
  [authentication.md](authentication.md) — the same `jwks_uri`/issuer
  guards apply regardless of which component is doing the federation.
- **Elevation of privilege / tampering via a compromised third-party
  SDK — open, not mitigated.** See §4.

## 4. Residual risks, stated honestly

- **No process-level isolation between connector code and
  secret-handling code.** Everything in §3 defends against a
  *malicious input* reaching a connector call — it does not defend
  against a *compromised dependency* (a vulnerability in the AWS/Azure/
  GCP SDK itself, for example) running with the same process privileges
  as the code that holds the KEK/DEK and decrypted secret values. There
  is no sandboxing, separate process, or separate container boundary
  between connector execution and the rest of the server today. Filed
  as [#2734](https://github.com/keyorixhq/keyorix/issues/2734)
  (`threat-model-gap`) — this is a design-exploration gap, not a known
  exploit; whether the engineering cost of a sandboxed
  connector-execution model is worth it is a product decision for
  Andrei, not something this document prescribes.
- **No Keyorix-native network egress-policy layer.** Per
  `../architecture.md` §6: outbound reachability is bounded by the
  per-call SSRF guards above and by the operator's own network/firewall
  configuration, not by an application-level allow/deny-list of
  destinations. Stated as a deliberate scope boundary, not an oversight.
