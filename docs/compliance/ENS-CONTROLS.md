# Keyorix Controls Mapping — ENS (Esquema Nacional de Seguridad)

This document maps Keyorix's **implemented** technical controls onto the security
measures of Spain's *Esquema Nacional de Seguridad* (ENS), governed by **Real
Decreto 311/2022** (Anexo II — *Medidas de seguridad*). It is the ENS-oriented
companion to the [NIS2 · DORA · ISO 27001 controls statement](./NIS2-DORA-ISO-CONTROLS.md);
both describe the same shipped capabilities, viewed through different frameworks.

> **Positioning.** Keyorix is **not** ENS-certified. ENS conformity is assessed at
> the level of an *information system* and is largely the **operator's**
> responsibility (security policy, risk analysis, categorisation, personnel, and
> the physical/operational environment). This document describes the product
> capabilities that **support** an operator's ENS compliance for the
> secret-management function. Measure families (`op.acc`, `op.exp`, `mp.info`,
> `mp.com`, …) are stable; confirm the exact sub-measure codes and your system's
> **categoría** (BÁSICA / MEDIA / ALTA) and applicability with a licensed ENS
> auditor (*entidad de certificación*). See [`README.md`](./README.md).

## Security dimensions covered

ENS rates systems across five dimensions. Keyorix's capabilities support all five
for the secrets it manages:

| Dimension | How Keyorix supports it |
|-----------|-------------------------|
| **Confidencialidad (C)** | AES-256-GCM encryption at rest; scoped RBAC; TLS in transit; no plaintext secrets in logs |
| **Integridad (I)** | AES-GCM authenticated encryption (AAD-bound); tamper-evident audit hash chain; signed-JWT federation |
| **Autenticidad (A)** | Hashed, single-purpose credentials; asymmetric JWT verification; per-action actor attribution |
| **Trazabilidad (T)** | Complete, append-style activity log with actor/timestamp/outcome; SIEM export |
| **Disponibilidad (D)** | Operator-owned PostgreSQL durability; documented backup/restore of DB **and** key material; on-prem/air-gap deployment |

## Measure mapping

### Marco operacional — Control de acceso (`op.acc`)

**Keyorix provides:**
- **Identificación (op.acc.1)** — every principal is a distinct identity: human
  users and, modelled separately, **machine identities** (service / CI /
  Kubernetes). No shared/anonymous access to secrets.
- **Requisitos / gestión de derechos de acceso (op.acc.2, op.acc.4)** — scoped
  **RBAC** enforced server-side on every request (`core.Authorize(user,
  permission, scope)`), identically on the HTTP and gRPC surfaces, at **system /
  project / environment** scope. A 5-state project-membership lifecycle governs
  grant and revocation; role and permission changes are audited.
- **Segregación de funciones (op.acc.3)** — distinct admin / auditor / viewer
  roles at both system and project tiers; least-privilege defaults
  (`system_viewer`); a user cannot grant permissions they do not hold, and
  cross-project (cross-tenant) operations are rejected when the caller is not
  authorised in the target project.
- **Mecanismo de autenticación (op.acc.5, op.acc.6)** — short-lived session
  tokens with a hard absolute-lifetime ceiling; a configurable password policy
  (length, complexity, common-password denylist, history, max-age); federated
  authentication for machine identities via **OIDC / Kubernetes-JWT** (signed,
  audience- and issuer-validated). **TOTP MFA (ADR-034) and phishing-resistant WebAuthn/passkeys (ADR-036) are shipped** — per-user opt-in second factors with two-step login + recovery codes; either satisfies a deployment-wide `security.require_mfa` mandate.

**Status:** Shipped.

### Marco operacional — Registro de la actividad (`op.exp.8`)

**Keyorix provides** (full treatment in [`AUDIT-LOG-PROVISIONS.md`](./AUDIT-LOG-PROVISIONS.md)):
- A complete activity log of every security-relevant event (secret CRUD, sharing,
  authentication success/failure, RBAC changes, membership transitions,
  impersonation start/end), each carrying **actor identity, timestamp, and
  outcome** — the core ENS *registro de actividad* requirement, with proportionate
  detail for higher categorías.
- **Tamper-evidence** — a SHA-256 **hash chain** over audit events makes any
  modification, deletion, insertion, or reorder detectable
  (`GET /api/v1/audit/verify`), supporting integridad/trazabilidad of the log
  itself.
- **Actor attribution** including delegated actions (`impersonated_by`/
  `acting_as`), and **SIEM** export (Splunk / Datadog / webhook + pull export).

**Status:** Shipped (SIEM forwarding Operator-configured).

### Marco operacional — Protección de claves criptográficas & monitorización

**Keyorix provides:**
- **Protección de claves criptográficas** — envelope encryption: a Data
  Encryption Key (DEK) wrapped by a passphrase-derived Key Encryption Key (KEK,
  PBKDF2, 600k iterations); the wrapped DEK and KEK salt live on a dedicated
  persisted volume; KEK bytes are wiped from memory after unwrap. Operator-driven
  **key rotation** re-encrypts every stored secret under the new DEK (the sweep is
  ordered so the rotation is complete — no row left under the old key) and the
  self-hosting runbook documents backup/restore of the key material.
- **Detección de intrusión (op.mon.1)** — built-in anomaly detection (e.g.
  brute-force / unusual access), deduplicated within a detection window.

**Status:** Shipped.

### Medidas de protección de la información (`mp.info`)

**Keyorix provides:**
- **Cifrado de la información (mp.info.3)** — every secret value is encrypted at
  rest with **AES-256-GCM**; Additional Authenticated Data binds each ciphertext
  to its `secretID:projectID:version`, preventing ciphertext substitution between
  secrets.
- **No plaintext exposure** — no secret values, passphrases, key bytes, or raw
  tokens are written to logs (audited across every sink); reusable credentials are
  SHA-256-hashed at rest and never compared in plaintext.

**Status:** Shipped.

### Medidas de protección de las comunicaciones (`mp.com`)

**Keyorix provides:**
- **Confidencialidad (mp.com.2)** — TLS in transit, via the bundled opt-in Caddy
  auto-HTTPS profile (publicly-trusted certificate for a real domain) or
  server-level TLS for the single-binary deployment; HSTS and a strict
  Content-Security-Policy are shipped.
- **Autenticidad e integridad (mp.com.3)** — federation tokens are verified with
  asymmetric signatures only (`HS*`/`none` rejected), with the issuer's signing
  keys fetched **over https** (key-MITM is refused by construction); audience and
  issuer are enforced.

**Status:** Shipped (in-transit TLS Operator-configured).

### Marco organizativo (`org.*`) — operator responsibility

ENS's organisational measures (security policy `org.1`, normativa `org.2`,
procedimientos `org.3`, proceso de autorización `org.4`) are the **operator's** to
define. Keyorix supports them operationally: enforceable RBAC and membership
processes, an authorisation/approval workflow for access requests, and a complete
audit trail that evidences that the operator's procedures are followed.

## Summary matrix

| ENS measure family | Dimension(s) | Keyorix capability | Status |
|--------------------|--------------|--------------------|--------|
| `op.acc` — Control de acceso | C, A | Scoped RBAC, machine identities, membership lifecycle, password policy, OIDC, TOTP MFA, WebAuthn/passkeys | Shipped |
| `op.exp.8` — Registro de actividad | T, I | Full audit trail + tamper-evident hash chain + SIEM | Shipped |
| Protección de claves criptográficas | C, I | Envelope encryption, KEK/DEK, rotation sweep, key backup | Shipped |
| `op.mon` — Monitorización | T | Anomaly detection | Shipped |
| `mp.info.3` — Cifrado | C, I | AES-256-GCM at rest, AAD-bound | Shipped |
| `mp.com` — Comunicaciones | C, A, I | TLS in transit; signed/validated federation | Shipped (TLS operator-configured) |
| `org.*` — Marco organizativo | — | Supported operationally; operator-defined | Operator |

> The technical-control evidence behind these claims — the security audits
> performed and the issues found and fixed — is recorded in
> [`SECURITY-VERIFICATION.md`](./SECURITY-VERIFICATION.md).
