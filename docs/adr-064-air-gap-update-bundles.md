# ADR-064: Air-gap update bundles — format, signing & offline verify (ADR-062 Phase 1a)

## Status

Accepted. Implements the **bundle** half of [ADR-062](adr-062-air-gap-updates.md) Phase 1;
see [air-gap-updates-design.md](air-gap-updates-design.md) §3. Builds on the Phase 0 trust
foundation (`internal/trust`). Phase 1a added the format + `build`/`verify`; Phase 1b adds
`import` — verified, no-downgrade-gated, atomic **staging** of the components to a
directory. Loading images into the internal registry and the Helm upgrade stay the
operator's own steps by design; CI publication of the bundle is the remaining 1b piece.

## Context

Air-gapped and highly-regulated deployments — the data-sovereignty segment Keyorix targets
(defence, finance, government; NIS2/DORA supply-chain integrity) — cannot reach the
internet to pull GHCR images and GitHub-Release artifacts. They need a single, verifiable
file they can carry across the gap and check **offline**, with cryptographic provenance and
anti-downgrade, trusting only a key pinned into the binary — never a key shipped inside the
artifact.

Phase 0 (ADR-062, #441) already shipped the verify-only foundation: `internal/trust`, a
purpose-scoped `ed25519` public-key registry that embeds trusted keys at build time via
`-ldflags` and **fails closed** (a plain `go build` trusts nothing). What was missing is the
bundle itself: a format, a way to build and sign it, and an offline verifier.

## Decision

Add `internal/bundle` and a `keyorix bundle` CLI with two commands.

**Format.** A bundle is a gzip-compressed tar. The first two entries are `manifest.json`
(version, `released_at`, `min_upgrade_from`, signing `key_id`, and every component pinned
by `sha256` + size) and `manifest.sig` (a detached `ed25519` signature over the exact
`manifest.json` bytes). All remaining entries are the pinned component files (images,
charts, CRDs, binaries, migrations). Signing the manifest transitively authenticates the
whole bundle: verify the signature, then verify each file's digest against the manifest.

**Trust.** Verification uses the `key_id` named in the manifest to select a key from the
**embedded** trust registry (`trust.PurposeUpdate`). It trusts only embedded, pinned keys —
a forged `key_id` is not in the registry, and an attacker cannot sign with a trusted
private key (the key never ships). The manifest is signed over its canonical (deterministic,
sorted-components) bytes, so the same inputs reproduce byte-identical, re-verifiable output.

**Verify is streaming and fail-closed.** It reads the manifest + signature first (size-
bounded), checks the signature, then streams each component, hashing it against its pinned
digest with the read bounded to the pinned size (a decompression-bomb guard that also
rejects an oversized entry). It rejects an unlisted file, a missing component, a digest
mismatch, an unknown/untrusted key, or an unconfigured purpose — every failure mode returns
an error and surfaces nothing.

**Anti-downgrade.** `CheckUpgrade(installed)` refuses a bundle whose version is not strictly
newer than what is installed, and enforces `min_upgrade_from` (anti-skip). A first install
(empty installed version) passes.

**CLI.**
- `keyorix bundle build --src <dir> --version vX.Y.Z --key-id <id> --sign-key <pkcs8.pem>
  [--min-upgrade-from vA.B.C] --out <file>` — the issuance side (Keyorix/CI), signing with
  the offline private key minted by `keyorix trust keygen`.
- `keyorix bundle verify <file> [--installed-version vX.Y.Z]` — the air-gapped operator
  side, verifying offline against the embedded pinned key and reporting version, key-id, and
  components. Fails closed.

## Alternatives considered

- **Sign each artifact separately (cosign/sigstore).** Strong tooling, but sigstore's
  default flow is online (transparency log, Fulcio) — the opposite of air-gap — and it
  fragments provenance across many signatures. A single signed manifest pinning everything
  is one artifact, one signature, offline by construction.
- **Detached signature + checksums.txt (the existing release output).** Already SHA-256s
  the artifacts, but the checksum file is unsigned and the artifacts are many files, not one
  carriable, anti-downgrade-aware unit.
- **Buffer the whole bundle to verify.** Simpler, but images make bundles large; streaming
  + per-entry size bounds keep verification memory-flat and bomb-resistant.

## Consequences

- Additive and behaviour-neutral: no caller verifies bundles at runtime yet, and a non-
  release build embeds no keys (every verify fails closed). Producing signed bundles is an
  operational step gated on embedding the production update key.
- `import` stages verified components to disk through one streaming pass shared with
  `verify` (`process`), gating no-downgrade *before* any write and writing each component
  atomically (temp + rename) so a digest failure never leaves a poisoned file. Loading the
  staged images into an internal registry and the Helm upgrade stay operator-controlled —
  the CLI prints those steps rather than performing them.
- Remaining 1b work: CI wiring (`bundle build` as a `release.yml` step publishing the
  bundle as a release asset) once a production update-signing key is embedded, and an
  optional server-side audit event when an import runs.
- Maps to a future "supply-chain integrity" compliance control (NIS2 Art. 21, DORA ICT
  third-party risk, ENS `op.exp.*`).
