# ADR-062: Air-gapped updates & offline license validation

## Status

Accepted (design). Implementation phased; see
[air-gap-updates-design.md](air-gap-updates-design.md).

## Context

Air-gapped, regulated customers (defence, finance, government — the data-sovereignty
segment Keyorix targets) cannot reach the internet. Today updates ship as GHCR images +
GitHub-Release artifacts (network-bound, no single verifiable carry-across artifact), and
there is no commercial entitlement mechanism (the product is AGPL-3.0). To answer an
air-gap prospect with "designed, ~4 weeks to ship," the architecture is decided now and
built on first pull (roadmap P2 #15).

Existing signing is **HMAC** (DEK-derived, symmetric) for evidence/audit integrity — the
verifier holds the key. That model cannot work across an air gap, where the customer must
verify *without* the signing secret.

## Decision

Adopt two cryptographically-verifiable, offline mechanisms, both built on **asymmetric
`ed25519`** signatures with **embedded, pinned public keys** (verify the trust chain, not
a self-described signature):

1. **Update bundles.** A single signed tarball wrapping the release artifacts (images,
   CLI/agent/operator/MCP binaries, charts, CRDs, migrations) with a `manifest.json` that
   pins every component by sha256 and an `ed25519` `manifest.sig`. Customer-side
   `keyorix bundle verify`/`import` verifies against the embedded update-signing public
   key, enforces no-downgrade, and stages artifacts into the internal registry. The
   private key never ships; the public key's fingerprint is published out-of-band.

2. **Offline license validation.** A signed (`ed25519`, separate keypair) license token
   carrying licensee/plan/features/`not_after`/optional `deployment_id`, verified locally
   against the embedded license public key. **Enforcement is fail-safe**: a
   missing/expired/invalid license degrades to the AGPL community baseline with a loud
   admin warning + audit event — it never denies access to existing secrets or stops the
   server (availability is a security property; a license lapse must not brick a secrets
   manager). It gates commercial features only. No phone-home.

Delivery is phased (keypairs+embedding → bundles → licensing → hardening), each phase its
own ADR; nothing changes default behaviour until built.

## Alternatives considered

- **Reuse the existing HMAC signing.** Rejected: symmetric — the customer would need the
  signing secret to verify, which is exactly what must not leave Keyorix.
- **Online license check / phone-home.** Rejected: defeats the air-gap requirement and
  adds an egress channel regulated buyers forbid.
- **Hard license enforcement (shutdown on expiry).** Rejected: bricking a running secrets
  manager on a license lapse is a worse outage than any revenue it protects; fail-safe
  degradation with audit is the correct posture.
- **Sign the bundle with the in-bundle key / cosign-keyless.** Rejected: keyless/OIDC
  provenance needs network; a key carried in the bundle is forgeable. Pin an embedded
  public key.
- **Single keypair for both.** Rejected: separate update- and license-signing keys keep
  blast radii independent.

## Consequences

- Two `ed25519` keypairs become release/issuance infrastructure; their public keys are
  embedded at build time and rotated via `key_id` + a transition window.
- New CLI surface (`bundle build|verify|import`, `license issue|install|status`) and a
  `release.yml` bundle-assembly step land in later phases.
- A "supply-chain integrity / verifiable updates" control can be added to the compliance
  posture (ADR-051) once bundles ship, mapping to NIS2/DORA/ENS supply-chain provenance.
- The mechanism composes with, and does not replace, AGPL-3.0 or the existing HMAC
  evidence/audit integrity.
