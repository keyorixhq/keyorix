# Threat Model: Update Bundles (Air-Gapped)

> Part of [`docs/security/threat-models/`](README.md). Derived from
> [`../architecture.md`](../architecture.md) §8. Covers the mechanisms
> that let an air-gapped deployment — no outbound internet access at
> all — still update and license itself without ever phoning home.

## 1. System context

An internet-connected secrets manager would normally check for updates
and validate licenses against a vendor server. Keyorix's default
operating mode has no such outbound dependency; three mechanisms extend
that to updates and licensing specifically, each using asymmetric
signing so the customer never needs to hold (or trust a channel
delivering) a shared secret.

```mermaid
flowchart LR
    subgraph Online["Build/release (online, Keyorix-controlled)"]
        BUILD[Release artifacts:\nimages, CLI/agent/operator/MCP\nbinaries, charts, CRDs, migrations]
        MANIFEST["manifest.json\n(SHA-256 per component)"]
        SIGN["ed25519 sign\n(update-signing keypair)"]
        LICSIGN["ed25519 sign\n(SEPARATE license keypair —\nblast radius doesn't overlap)"]
    end

    subgraph Bundle["Signed bundle (offline transfer)"]
        TARBALL[("Single tarball")]
    end

    subgraph Airgap["Air-gapped customer environment (no egress)"]
        PUBKEY1["Embedded, pinned\nupdate public key"]
        PUBKEY2["Embedded, pinned\nlicense public key"]
        VERIFY["keyorix bundle verify/import"]
        LICCHECK["Offline license validation\n(internal/license)"]
        OIDCOFFLINE["Air-gapped OIDC\n(ADR-075 — no live JWKS\nreachability needed)"]
    end

    BUILD --> MANIFEST --> SIGN --> TARBALL
    TARBALL --> VERIFY
    PUBKEY1 --> VERIFY
    LICSIGN --> LICCHECK
    PUBKEY2 --> LICCHECK
```

## 2. Trust boundaries

| Boundary | Enforcement |
|---|---|
| Bundle authenticity | `ed25519` signature verified against an **embedded, pinned** public key — never fetched at verify time, so there's no network call to intercept |
| License authenticity | A **separate** `ed25519` keypair from update signing, so a compromise of one blast radius doesn't extend to the other |
| Component integrity within a bundle | `manifest.json` pins every component (images, binaries, charts, CRDs, migrations) by SHA-256 |
| OIDC federation with no live JWKS reachability | ADR-075 — machine-identity OIDC verification works for Kubernetes/CI environments that themselves have no egress |

## 3. STRIDE

- **Tampering — bundle substitution/modification in transit.** The
  signature is asymmetric specifically because an air-gapped customer
  must be able to verify without ever holding the signing secret —
  unlike the audit chain's symmetric HMAC checkpoints (see
  [audit-chain.md](audit-chain.md)), which assume the verifier *does*
  hold the key. `keyorix bundle verify`/`import` reject anything not
  matching the pinned public key.
- **Spoofing — forged license.** A compact
  `base64url(payload).base64url(sig)` token evaluated entirely locally
  against the second, independent embedded public key; no phone-home,
  ever, by design (ADR-065) — a licensing call-home would itself be an
  exfiltration channel a regulated buyer would reject.
- **Information disclosure — license/update call-home as a covert
  channel.** Explicitly not possible by construction: neither mechanism
  makes any outbound network call at verification time. This is the one
  property this threat model can state with full confidence rather than
  "no instance found" — there is no code path that attempts a network
  call in either verifier.
- **Elevation of privilege — a commercial-tier-gated feature bypassed.**
  `airgap_updates` (gating `keyorix bundle import`) is the first
  commercial-tier-gated feature. A gate that fails open on a licensing
  error would let an unlicensed install import bundles anyway.
  **Not independently re-verified for this document** — see §4.

## 4. Residual risks, stated honestly

- **Implementation completeness is phased and only partially
  independently confirmed.** `../architecture.md` §8 itself states:
  "ADR-062 itself is recorded as 'Accepted (design), implementation
  phased' — the license (Phase 2a/2b/2c) and bundle-verify mechanisms
  above are confirmed present in code (`internal/license`,
  `internal/cli/bundle`); this document does not claim every phase named
  in that ADR's original design is complete, only what is independently
  verified to exist." This threat model inherits that same caveat rather
  than overstating completeness.
- **The commercial-tier gate's fail-closed behavior under a licensing
  error was not independently re-verified while writing this document.**
  This document asserts the gate exists (`airgap_updates`) but did not
  trace its behavior end-to-end under a corrupted/expired license token.
  If this matters for a specific evaluation, trace `internal/license`'s
  gate check directly rather than relying on this document's general
  statement.
