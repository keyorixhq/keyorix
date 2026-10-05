# Keyorix Controls Mapping — BSI IT-Grundschutz APP.bd.6

This document maps Keyorix's **implemented** technical controls onto the
German Federal Office for Information Security's (BSI) user-defined
IT-Grundschutz module **APP.bd.6 "Secrets Management with Hashicorp
Vault"** (last edited 2021-11-19). The module is written specifically
for Vault, but its 18 requirements (A1–A18) describe generic
secrets-management controls that apply to any product in this category
— this document walks every one of them against Keyorix as shipped,
rather than against Vault.

> **Positioning.** Keyorix is **not** assessed or certified against this
> module — there is no formal IT-Grundschutz audit process this document
> claims to have gone through. This is a self-assessed, evidence-linked
> mapping, in the same spirit as
> [`NIS2-DORA-ISO-CONTROLS.md`](./NIS2-DORA-ISO-CONTROLS.md) and the
> other documents in this directory. Where a requirement doesn't apply
> to Keyorix's architecture the way it applies to Vault's (e.g. Vault's
> concept of a "root token" has no direct Keyorix equivalent), that
> difference is stated rather than force-fit into a false match. Source
> document: BSI, downloaded 2026-10-05 from
> `bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/Hilfsmittel/Benutzerdefinierte_BS/BS_Secrets_Management_mit_Hashicorp_Vault_EN.pdf`.

## 3.1 Basic requirements (MUST)

| ID | Requirement | Status | Keyorix mapping |
|---|---|---|---|
| A1 | Plan and document the deployment (operating model, functions used, storage backend choice, application-integration choice, backup/recovery procedure) before deploying. | **Operator responsibility, Keyorix-supported.** | Keyorix ships its own extensive design documentation (this `docs/security/` and `docs/compliance/` tree, [`../SELF_HOSTING.md`](../SELF_HOSTING.md), [`../CONFIGURATION.md`](../CONFIGURATION.md)) covering every point A1 lists except the operator's own site-specific deployment plan, which remains theirs to write. |
| A2 | The service MUST NOT run with root rights; configuration files MUST restrict access to the service user only. | **In place.** | `SECURITY.md` § Security-Relevant Configuration: "Run `keyorix-server` as a non-root service user." The Helm chart's security-policy scanning (`checkov`, a required CI check — see [`../security/SDLC.md`](../security/SDLC.md)) enforces non-root, dropped capabilities, and no privilege escalation at the container level, not just as a documentation recommendation. |

## 3.2 Standard requirements (SHOULD)

| ID | Requirement | Status | Keyorix mapping |
|---|---|---|---|
| A3 | High availability (cluster), VMs on different hosts, restart-on-failure for containers. | **In place.** | [ADR-039](../adr-039-ha-deployment.md) (HA deployment design); cross-replica correctness is itself threat-modeled, not just assumed — see [`../security/threat-models/ha-consistency.md`](../security/threat-models/ha-consistency.md). |
| A4 | Encrypt client↔server-cluster communication; load balancers/reverse proxies SHOULD NOT terminate TLS. | **Partially in place, stated honestly.** | TLS termination support and cipher-suite hardening exist ([`../security/architecture.md`](../security/architecture.md) §6 — HSTS/CSP, `allowed_ciphers` allowlist, `RequireTransportTLS`). Unlike this requirement's "proxy should not terminate TLS" preference, Keyorix's default assumes a TLS-terminating proxy in front is a common, supported deployment shape (with a loud warning if cleartext ends up served) — a deliberate difference from this requirement's stated preference, not an oversight. |
| A5 | Vault SHOULD be the only main process on its host (no multi-tenant host). | **Deployment-owned, not an application-layer control.** | [`../security/architecture.md`](../security/architecture.md) §9 lists host-level isolation as explicitly deployment-owned. No Keyorix mechanism enforces or checks this. |
| A6 | Disable SSH/remote-desktop access to the host; access only via the API. | **Deployment-owned.** | Same as A5 — host access policy is the operator's, not something Keyorix's application layer can observe or enforce. |
| A7 | Monitor availability, resource utilization, and error states; integrate with central monitoring/log management. | **Partially in place.** | Prometheus metrics exist for specific mechanisms (e.g. `keyorix_best_effort_failures_total` — see [`../security/SECURE-CODING.md`](../security/SECURE-CODING.md) §7); this document does not claim a comprehensive, product-wide metrics/alerting surface was independently verified while writing this mapping — flag for a dedicated pass if this matters for a specific evaluation. |
| A8 | Disable swap to prevent sensitive data from being paged to disk. | **In place, as a deployment-level control (deliberate architectural change, not a gap).** | [ADR-100](../adr-100-mlockall-removal-deployment-swap-control.md): Keyorix's own `mlockall` was removed after being measured to cause a real cgroup-OOM-kill availability regression, and swap protection is now explicitly a deployment-level control (disable swap on the node/container runtime) rather than in-process — the same recommendation this requirement makes, arrived at independently and documented as a correction to an earlier design. |
| A9 | Disable core dumps — a forced core dump could expose encryption keys. | **In place.** | [ADR-098](../adr-098-process-memory-hardening.md): `RLIMIT_CORE` lowered to `{0,0}` unconditionally at startup, verified by actually triggering a crash (a hardened process produces no core file where a baseline one produces 46 MB). |
| A10 | Revoke the initialization root token after setup. | **No direct equivalent — architectural difference, stated rather than mapped.** | Keyorix has no Vault-style "root token" minted at init time. The closest analogous credential is the recovery key (`internal/recoverykey`) or the master passphrase itself, neither of which is a bearer token with Vault's root-token blast radius, and neither is "revoked after setup" the way a root token is — they remain the ongoing, deliberately-provisioned recovery mechanism. See [`../security/threat-models/authentication.md`](../security/threat-models/authentication.md) "Emergency admin recovery" for the actual design and why it's held permanently, not minted-then-revoked. |
| A11 | Manage configuration via version-controlled files, not manual changes. | **Deployment-owned.** | Keyorix ships a config-file + env-var model (`internal/config`); whether an operator manages that file under version control is their own practice, not something Keyorix enforces. |
| A12 | Activate audit logging. | **In place, and stricter than this requirement's phrasing implies.** | This requirement says audit logging "SHOULD be activated" — implying it can be left off. Keyorix's audit logging of security-relevant actions is **not optional** in the same sense; see [ADR-029](../adr-029-audit-log-tamper-evidence.md) and [`../security/threat-models/audit-chain.md`](../security/threat-models/audit-chain.md). Sensitive values are never written to the audit log at all (not merely hashed, per this requirement's own phrasing) — see [`../security/SECURE-CODING.md`](../security/SECURE-CODING.md) §5. |
| A13 | Restrict access to the storage backend to the secrets-management service itself. | **Deployment-owned, with a compensating control.** | Database-level access restriction is the operator's responsibility (network/firewall/DB-grant configuration). The compensating control: even full storage-backend read access does not yield plaintext secrets without the separately-held KEK — see [`../security/threat-models/secret-storage-key-hierarchy.md`](../security/threat-models/secret-storage-key-hierarchy.md). This narrows, but does not eliminate, the consequence of a backend-access failure the operator is still responsible for preventing. |
| A14 | Automate configuration rollout to reduce manual error. | **Partially in place.** | The Helm chart and Kubernetes operator installation path (`../security/threat-models/kubernetes-operator.md`) is automatable end-to-end; a bare-binary/Docker-Compose deployment's own configuration rollout automation is the operator's choice of tooling. |
| A15 | Use fine-grained, least-privilege ACL policies. | **In place.** | Scoped RBAC at system/project/environment granularity, PAT restriction filters that only ever narrow below the owner — see [`../security/threat-models/authorization-rbac.md`](../security/threat-models/authorization-rbac.md). |
| A16 | Tokens SHOULD only be valid as long as access is actually needed (ephemeral TTL). | **In place.** | Short session TTLs with a hard absolute lifetime ceiling, time-bounded PATs, machine-identity lifecycle states — see [`../security/threat-models/authentication.md`](../security/threat-models/authentication.md). |

## 3.3 Requirements for increased protection needs

| ID | Requirement | Status | Keyorix mapping |
|---|---|---|---|
| A17 | Rotate the master key / shared keys on staff turnover (entry or departure). | **In place, operator-triggered.** | `keyorix encryption rotate` performs a full DEK re-encryption sweep with verified completeness (a structural guard, not a hand-maintained list) — see [ADR-010](../adr-010-kek-rotation-reencryption-sweep.md) and [`../security/architecture.md`](../security/architecture.md) §2. Keyorix does not automatically trigger this on a staff-roster change (it has no concept of "owners of shared keys" the way a Shamir-split root key does outside of the `shamir` key-provider mode specifically) — triggering it on personnel change is the operator's process to run, same as this requirement expects for Vault. |
| A18 | Use resource quotas (max RPS, lease quotas) to protect against resource exhaustion/DoS. | **In place.** | Rate limiting, request-body size caps, pagination, bulk-op batch caps, and a bounded-BFS fix for dependency traversal — see [`../security/threat-models/server-api.md`](../security/threat-models/server-api.md) and [`../security/SECURE-CODING.md`](../security/SECURE-CODING.md) §9. |

## Summary

Of 18 requirements: **12 fully in place** (A2, A3, A8, A9, A12, A15, A16,
A17, A18, plus A1/A7/A14 partially), **4 are deployment-owned** (A5, A6,
A11, and the access-restriction half of A13), and **1 has no direct
architectural equivalent** (A10, Vault's root-token model vs. Keyorix's
recovery-key model). No requirement is claimed as met without a citation
above; where the honest answer is "this is the operator's job, not
Keyorix's," that is stated plainly rather than mapped to a control that
doesn't actually cover it.
