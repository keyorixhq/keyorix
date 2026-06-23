# Design: air-gapped updates & offline license validation

> **Status: design (not yet built).** This document is the "designed, ~4 weeks to ship"
> answer for an air-gapped/regulated prospect. It is intentionally produced ahead of
> implementation (roadmap P2 #15); build phases land on the first real air-gap pull. The
> architectural decision is recorded in [ADR-062](adr-062-air-gap-updates.md).

## 1. Problem & motivation

Air-gapped and highly-regulated deployments (defence, finance, government — exactly the
data-sovereignty segment Keyorix targets) cannot reach the internet. Two gaps block them
today:

1. **Updates require network.** New versions ship as GHCR images + GitHub-Release
   binaries/charts ([RELEASING.md](../RELEASING.md)). An isolated environment can't pull
   them, and there is no verifiable, single-artifact way to carry an update across the
   gap with provable provenance.
2. **No offline entitlement.** Keyorix is AGPL-3.0 ([LICENSE_GUIDE](LICENSE_GUIDE.md)) and
   has no commercial entitlement mechanism. A paid tier for air-gapped customers needs a
   license that validates **without phoning home**.

This is a differentiation play, not table stakes: competitors' catalogues are
cloud-centric. "Updates and licensing that work with no internet, with cryptographic
provenance" is a concrete answer regulated buyers ask for by name (NIS2/DORA supply-chain
integrity; ENS).

### What exists to build on

- **Signing primitives.** Internal integrity uses **HMAC** (DEK-derived, `<keyVersion>:<hmac>`)
  for evidence packs and audit checkpoints (`internal/core/evidence_signing.go`,
  `audit_checkpoint.go`) — symmetric, server-held. `ed25519` is already a dependency
  (OIDC JWKS, `internal/core/oidc_jwks.go`).
- **Offline awareness.** `internal/cli/offline` detects connectivity but does not handle
  bundles or licensing.
- **Release pipeline.** `release.yml` already emits `checksums.txt` (SHA-256) and packages
  charts; `docker-publish.yml` builds the images. These are the inputs a bundle wraps.

**Key insight:** the existing HMAC signing is unsuitable here — the customer must *verify*
without holding the signing secret. Air-gap artifacts require **asymmetric** signatures
(`ed25519`): Keyorix signs with a private key it never ships; the binary verifies against
an **embedded, pinned public key**. This follows the "verify the trust chain, not just a
self-consistent signature" principle.

## 2. Goals / non-goals

**Goals**
- A single, verifiable **update bundle** an operator imports into an air-gapped cluster,
  covering the server image, CLI, agent/operator/MCP images, Helm charts, CRDs, and DB
  migrations.
- **Offline license validation**: a signed license file checked locally, gating
  commercial features and recording entitlement, with no network dependency.
- Cryptographic **provenance + integrity + anti-downgrade**; deterministic and auditable.

**Non-goals**
- Online/auto-update.
- DRM that can brick a running deployment (availability is a security property).
- Replacing AGPL-3.0 for the open-source core.

## 3. Update bundles

### 3.1 Format

A bundle is a tarball `keyorix-update-<version>.bundle` (a deterministic, reproducible
archive):

```
manifest.json            # version, component list, each component's sha256, min-from version
manifest.sig             # ed25519 detached signature over manifest.json
images/                  # OCI layout (docker save / oci-layout) for each image
charts/                  # keyorix*.tgz Helm charts
crds/                    # CRDs (e.g. secrets.keyorix.io_keyorixsecrets.yaml)
migrations/              # forward DB migrations for this version
bin/                     # keyorix, keyorix-server, agents (per-os/arch)
CHANGELOG.md
```

`manifest.json` pins **every** component by `sha256`, plus `version`, `released_at`,
`min_upgrade_from` (anti-skip), and the signing `key_id`. Signing the manifest therefore
transitively authenticates the whole bundle — verify the signature, then verify each
file's digest against the manifest.

### 3.2 Signing & trust

- **`ed25519` update-signing keypair.** Private key lives only in the release/issuance
  path (CI secret today; offline HSM-backed at scale). The **public key is embedded in
  the binary at build time** and its fingerprint published out-of-band (website, docs) so
  customers can pin it independently of any download.
- Verification trusts **only** the embedded pinned key (and its `key_id`), never a key
  carried in the bundle — defeating a swap-the-key forgery.
- **Key rotation:** a new binary release embeds the new public key while still honouring
  the previous `key_id` for a transition window; manifests carry `key_id` so a verifier
  selects the right pinned key.

### 3.3 Operator flow (CLI)

Build side (Keyorix):
- `keyorix bundle build --version vX.Y.Z` — assembles the bundle from release artifacts
  and signs the manifest (CI step extending `release.yml`).

Air-gap side (customer):
- `keyorix bundle verify <file>` — verifies `manifest.sig` against the embedded pinned
  key, then every component digest. Reports version, components, and the signing `key_id`.
  **Fails closed** on any mismatch.
- `keyorix bundle import <file> [--registry <internal-registry>]` — re-verifies, enforces
  `min_upgrade_from` / **no-downgrade** (refuse an older version than installed), loads
  images into the internal registry, stages charts/CRDs/binaries, and prints the exact
  `helm upgrade` to run. Import is idempotent and records an audit event.

The actual rollout stays the operator's existing `helm upgrade` + migration step — the
bundle only makes the artifacts **available and verified** offline.

## 4. Offline license / entitlement

### 4.1 License format

A compact, signed token (EdDSA JWS, or `base64url(payload).base64url(sig)`):

```json
{
  "licensee": "ACME Defence GmbH",
  "plan": "enterprise-airgap",
  "features": ["airgap_updates", "premium_connectors", "extended_retention"],
  "issued_at": "2026-06-01T00:00:00Z",
  "not_after": "2027-06-01T00:00:00Z",
  "deployment_id": "kx-7f3a…",        // optional binding (see 4.3)
  "max_seats": 250,                    // optional, informational
  "key_id": "lic-2026"
}
```

Signed with a **separate `ed25519` license-signing keypair** (distinct blast radius from
update signing). The verifier uses the **embedded license public key**.

### 4.2 Validation & enforcement posture

- Validate at startup and on a periodic timer: verify signature against the pinned key,
  check `not_after` (with a configurable **grace period**), and load the entitlement into
  an in-memory feature gate.
- **Fail-safe, not fail-closed.** A missing/expired/invalid license **degrades to the
  baseline (AGPL community) feature set** and raises a prominent admin warning + an audit
  event — it never deletes data, never denies access to existing secrets, and never stops
  the server. Rationale: for a secrets manager, availability *is* a security property; a
  license lapse must not brick production. Enforcement gates **commercial features only**.
- Surfaced in the compliance posture and `keyorix license status`; license state
  transitions (installed / expiring-soon / expired / invalid) emit audit events and admin
  notifications (reusing the existing reminder/notification machinery).

### 4.3 Anti-abuse (proportionate)

- Optional binding to a `deployment_id` minted at init, so a license can't be trivially
  copied between unrelated deployments. Mismatch → warning + audit, **not** a shutdown
  (consistent with fail-safe).
- Expiry + signature defeat forgery/replay; no phone-home means no exfiltration channel.

### 4.4 CLI surface

- Issuance (Keyorix-internal): `keyorix license issue …`.
- Customer: `keyorix license install <file>`, `keyorix license status`.

## 5. Key management & threat model

| Threat | Mitigation |
|---|---|
| Tampered bundle / image swap | `ed25519` manifest signature + per-component sha256; verify trusts only the embedded pinned key. |
| Downgrade / version skip | `no-downgrade` + `min_upgrade_from` enforced on import. |
| Forged or replayed license | `ed25519` signature + `not_after` + optional `deployment_id` binding. |
| Signing-key compromise | Private keys never shipped; rotation via embedded `key_id` + transition window; fingerprints published out-of-band. HSM-backed issuance at scale. |
| License lapse bricks prod | Fail-safe degrade-to-baseline; never destructive. |

Two independent `ed25519` keypairs (update-signing, license-signing) keep blast radii
separate. This composes with — not replaces — the existing HMAC integrity used for
evidence/audit (different trust model, different purpose).

## 6. Phased delivery

Each phase is independently shippable and gets its own ADR; nothing here changes default
behaviour until built.

1. **Phase 0 (now):** this design + ADR-062. Generate the two `ed25519` keypairs; embed
   the public keys at build time (`-ldflags`), no behaviour change.
2. **Phase 1 — bundles:** `keyorix bundle build` (CI, extends `release.yml`) +
   `verify`/`import`; bundle published as a release asset for online customers to relay.
3. **Phase 2 — licensing:** offline license verification, the commercial feature gate
   (fail-safe), `license install|status`, and compliance/audit surfacing.
4. **Phase 3 — hardening:** HSM-backed signing, key rotation drill, reproducible-bundle
   verification, and a documented operator runbook.

## 7. Compliance mapping

Supply-chain integrity and provenance (NIS2 Art. 21, DORA ICT third-party risk,
ENS `op.exp.*`), data-sovereignty / no-egress operation, and verifiable update control.
These map cleanly onto the existing control framework (ADR-051) and can be added to the
compliance posture as a "supply-chain integrity" control once Phase 1 lands.
