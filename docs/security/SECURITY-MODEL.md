# Keyorix Security Model

> **Format note.** This page follows the format HashiCorp Vault, OpenBao,
> and Infisical each publish for the same purpose — goals, in scope, out
> of scope, trust assumptions — because it's become the de facto
> standard shape for this kind of document, and there's no reason to
> make a reader re-learn a new structure. What differs is underneath: no
> secrets manager surveyed while writing this (including the three named
> above) publishes a full per-component STRIDE threat model with an
> evidence link per claim — that's what
> [`threat-models/`](threat-models/README.md) is, and every claim below
> links into it or into [`threat-model.md`](threat-model.md) rather than
> asserting on its own authority.

## Goals

Protect the confidentiality, integrity, and availability of secret
values and the account/audit data around them, for an operator running
Keyorix **entirely inside their own infrastructure** — there is no
Keyorix-operated cloud in the secret-resolution path, by design (see
[`architecture.md`](architecture.md) §8).

## In scope

- The Keyorix server process: encryption at rest, authentication
  (sessions, PAT, machine identity, OIDC, SAML SSO, TOTP, WebAuthn),
  scoped RBAC, the audit hash chain.
- The REST and gRPC API surface, and every client that talks to it
  (web UI, CLI in remote mode, SDKs, the Kubernetes operator/sync
  agent/ESO integration, the `keyorix-mcp` server).
- Outbound connector/rotation-target/KMS calls the server makes on an
  operator's behalf.
- Signed release artifacts, air-gapped update bundles, and offline
  licensing.
- **Cross-replica consistency in an HA deployment** — see
  [`threat-models/ha-consistency.md`](threat-models/ha-consistency.md).
  Listed as in scope explicitly because no comparable published security
  model names this threat class at all; it's a real failure mode for any
  multi-replica deployment, not specific to Keyorix, and deserves to be
  modeled rather than left implicit.

## Out of scope

The shared baseline below is the same one HashiCorp Vault, OpenBao, and
Infisical each publish, because it describes a real and common
boundary, not a Keyorix-specific evasion. Differences from that shared
baseline — where Keyorix's actual mitigation goes further, or where a
line is drawn differently — are called out explicitly rather than
silently copied.

1. **Arbitrary control of the storage backend.** An attacker who can
   execute arbitrary operations against the underlying SQLite/PostgreSQL
   database (not just read it) can cause damage no application-layer
   control fully prevents — see [`architecture.md`](architecture.md) §9
   for what stays deployment-owned (network segmentation, DB access
   control).
   **Where Keyorix differs from the shared baseline:** the audit hash
   chain is explicitly designed to make a subset of this class
   *detectable* even though it isn't *prevented* — modification,
   deletion, insertion, or reordering of a present audit row is caught
   by re-walking the chain, and tail-truncation/genesis-reseed is
   additionally caught by signed checkpoints and off-box anchors. See
   [`threat-models/audit-chain.md`](threat-models/audit-chain.md). This
   is a narrower claim than "storage compromise is survivable" — it's
   specifically "tampering with the audit trail via storage compromise
   doesn't go unnoticed," which is the part worth distinguishing.
2. **Leakage of secret existence via the storage layer itself.** Row
   presence/absence at the database level is not independently hidden
   from someone with direct DB access — this is a property of using a
   relational database as the backing store, not something an
   application-layer control changes.
3. **Memory analysis of the running server process** (a live memory
   dump, `ptrace`, or a privileged local attacker reading process
   memory). **Where Keyorix differs from the shared baseline:** this
   stays out of scope as a *guarantee*, but hardening exists and is
   claimed honestly as hardening, not prevention — core dump suppression
   (`RLIMIT_CORE`, [ADR-098](../adr-098-process-memory-hardening.md)) and
   real byte-by-byte key-material zeroization on every return path
   (`internal/encryption/wipebytes_sweep_test.go`) reduce what a memory
   capture *after the fact* can recover, without claiming to defeat
   live, in-process memory analysis. See
   [`threat-models/secret-storage-key-hierarchy.md`](threat-models/secret-storage-key-hierarchy.md)
   §4 for the specific, named residual: transient plaintext heap copies
   between decryption and the wire are not wiped, and this document does
   not claim otherwise.
4. **Compromised external authentication systems** — a compromised OIDC
   issuer or SAML IdP that signs a token/assertion for an identity it
   shouldn't. Keyorix verifies signatures and claims correctly; it
   cannot detect that the party holding the signing key has itself been
   compromised. See [`threat-models/authentication.md`](threat-models/authentication.md).
5. **Malicious plugins or arbitrary host code execution.** Keyorix has
   no plugin system; this line item exists mainly for consistency with
   the shared baseline shape, and to be explicit that
   [`threat-models/connectors.md`](threat-models/connectors.md)'s
   documented gap (no process-level isolation for connector/SDK code) is
   a *distinct* concern from a plugin system — there is no third-party
   plugin loading mechanism to begin with.
6. **Compromised client credentials.** A leaked, valid session/PAT/
   machine token is authenticated and authorized exactly as if its
   rightful holder used it, until revoked. Scoped RBAC, short TTLs, and
   revocation bound the blast radius; they don't prevent use of a token
   an attacker actually possesses.
7. **Malicious or vulnerable admin-level configuration.**
   **Where Keyorix differs from the shared baseline:** this is only
   *partly* out of scope. Secure-by-default configuration is actively
   enforced, not merely documented — `crypto.DetectFallbackDowngrade`
   makes a weak-fallback key-provider chain a hard startup error rather
   than a silent downgrade; `RequireTransportTLS` refuses to start an
   enabled listener with no TLS configured when set; the `insecure_`-
   prefixed opt-out convention (`internal/envflag`) defaults every such
   flag to disabled. See [`SECURE-CODING.md`](SECURE-CODING.md) §1 and
   §6. What stays out of scope: an admin who *deliberately* disables a
   secure default after being warned, or who grants another human
   account privileges they shouldn't have — that's a human decision no
   application control overrides.
8. **Prompt-injection-driven agent behavior**, for the `keyorix-mcp`
   component specifically — named here because the shared baseline above
   predates MCP and doesn't cover it. A secret's value is
   attacker-controllable content to anyone who can write it; once
   returned to an AI agent, Keyorix cannot detect or block the agent
   acting on injected instructions inside that content. See
   [`threat-models/mcp-server.md`](threat-models/mcp-server.md) MCP-3 —
   bounded (read caps, scoping) but not prevented, and stated as such
   rather than hidden behind a one-line disclaimer.
9. **Dependency vulnerabilities, physical access to hardware, and social
   engineering** — the same three items Infisical's published model adds
   to the Vault-derived shared baseline. Dependency vulnerabilities are
   mitigated, not eliminated, by the scanning/fuzzing programme in
   [`testing.md`](testing.md) and [`SDLC.md`](SDLC.md) § Dependency
   policy; physical access and social engineering are operator-side
   controls this product cannot enforce.

## Trust assumptions

- **The operator's own infrastructure is trusted up to the boundaries
  stated above** — host OS, network segmentation, and physical security
  are the operator's responsibility (see
  [`architecture.md`](architecture.md) §9).
- **Where the KEK lives determines what host root can and cannot do** —
  the single most consequential trust assumption in this whole model.
  See [`threat-model.md`](threat-model.md) §5.1 and
  [`threat-models/secret-storage-key-hierarchy.md`](threat-models/secret-storage-key-hierarchy.md)
  for the full file-KEK-vs-KMS/HSM distinction.
- **No independent third-party pentest has been performed as of this
  writing.** Several competitors surveyed for this document publish a
  pentest cadence (e.g. Doppler's annual HackerOne-coordinated pentest,
  Infisical's twice-yearly Cure53 engagements) — Keyorix does not have
  an equivalent today, and this document does not imply otherwise. The
  verification evidence this repository *can* currently offer is CI
  gates, fuzzing, and internal review — see [`testing.md`](testing.md)
  §6 "What this program does not claim."
