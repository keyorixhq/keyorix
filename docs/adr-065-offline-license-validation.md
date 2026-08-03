# ADR-065: Offline license validation (ADR-062 Phase 2)

## Status

Accepted. Implements the **licensing** mechanism of
[ADR-062](adr-062-air-gap-updates.md); see [air-gap-updates-design.md](air-gap-updates-design.md)
§4. Builds on the Phase 0 trust foundation (`internal/trust`, `PurposeLicense`). Phase 2a is
the token + offline evaluation + CLI; **Phase 2b** wired it into the server (startup load, a
nil-safe fresh-evaluating gate on the core, a startup audit event, `GET
/api/v1/license/status`); **Phase 2c** (this revision) designates the **first commercial
feature** — `airgap_updates`, gating `keyorix bundle import`, and adds the opt-in `license_expiry`
background reminder that notifies install-wide admins ahead of a lapse. Dashboard surfacing
(`web/`) remains.

## Context

Keyorix is AGPL-3.0 with no commercial entitlement mechanism. A paid tier for air-gapped
customers (defence/finance/government) needs a license that validates **without phoning
home** — there is no egress to a license server, and a phone-home would itself be an
exfiltration channel a regulated buyer would reject.

The Phase 0 trust registry already supports a `license` purpose with an embedded, pinned
`ed25519` public key (separate keypair from update signing, so the blast radii are
independent). What was missing is the license token, its offline evaluation, and the CLI.

## Decision

Add `internal/license` and a `keyorix license` CLI (`issue`, `install`, `status`).

**Token.** A compact `base64url(payload).base64url(sig)` token. The payload is JSON:
`licensee`, `plan`, `features[]`, `issued_at`, `not_after`, optional `deployment_id`,
optional `max_seats`, and the signing `key_id`. The signature is `ed25519` over the exact
payload bytes; verification decodes the payload bytes from the token and verifies against
the **embedded** license key named by `key_id` — trust follows the pinned chain.

**Fail-safe enforcement — the deliberate inverse of update bundles.** Bundles are
fail-CLOSED (an unverifiable bundle must never be trusted). A license is **fail-SAFE**:
`Evaluate` never returns an error. Every failure mode — no token, malformed token, bad
signature, untrusted/absent key, expiry beyond grace, deployment-binding mismatch —
degrades to the **community baseline** (no commercial features) with a `Reason` the caller
surfaces as a prominent admin warning and an audit event. It never deletes data, never
denies access to existing secrets, and never stops the server: for a secrets manager,
availability *is* a security property, and a license lapse must not brick production.
Enforcement gates **commercial features only**, through a single `Status.HasFeature` gate.

**States.** `active` (valid, in date) and `expiring_soon` both grant features;
`expiring_soon` covers the window before `not_after` *and* a configurable post-expiry
**grace** period (features are retained during grace so the server doesn't lose
entitlement the moment a license lapses — it warns instead). `expired` (past grace),
`invalid` (unverifiable / deployment-mismatch), and `none` (no license) all drop to
baseline.

**Anti-abuse (proportionate).** An optional `deployment_id` binds a license to one
deployment; a mismatch degrades to baseline with a warning, it does **not** shut down.
Expiry + signature defeat forgery and replay. No phone-home means no exfiltration channel.

**CLI.** `issue` (Keyorix-internal, signs with the offline license key) prints a token;
`install` validates a token and stores it at `0600` (refusing to store an unverifiable
one) for the server to load; `status` reports the locally-evaluated entitlement. A plain
(non-release) build embeds no license key, so every token evaluates to `invalid` →
baseline — and still exits cleanly, never denying.

## Alternatives considered

- **A real JWS/JWT library (EdDSA).** Standards-conformant, but pulls a dependency for a
  format we fully control; the compact `payload.sig` form is a few lines, dependency-free,
  and consistent with `internal/bundle` and `internal/trust`.
- **Online license check / floating seats.** Rejected outright — the whole point is no
  phone-home for air-gapped buyers; seats are informational (`max_seats`), not enforced
  online.
- **Fail-closed enforcement (deny on invalid license).** Rejected: bricking a running
  secrets manager on a license lapse is a worse outcome than running the community
  baseline. Fail-safe is the explicit ADR-062 posture.

## Consequences

- The first commercial feature is `airgap_updates`, gating `keyorix bundle import` (2c).
  It was chosen because it strips nothing from community source builds — import already
  requires the embedded update-signing key only release builds carry — and it is the
  air-gap tier's flagship by design (ADR-062). `bundle verify` stays free. The gate is
  fail-safe: a missing/expired/invalid license simply means the feature is off and import
  is refused with an actionable message; it never touches a running deployment.
- A non-release build trusts no license key, so evaluation is always baseline; gating is a
  no-op there (and import is impossible anyway without the embedded update key).
- The design's "validate on a periodic timer" is realised by the gate evaluating **freshly
  on every call** rather than caching a status and re-checking on a timer — a license that
  lapses while the server runs is observed on the next `Status()`/`HasFeature` call, with no
  goroutine to manage. `Evaluate` is cheap (one ed25519 verify), so per-call cost is
  negligible. A separate transition-notification path (2c) can still watch for state changes.
- `core.HasLicensedFeature` is the one gate 2c wires into commercial-feature call sites; the
  fail-safe semantics live entirely in `Evaluate`, so call sites stay trivial.
- Issuing real licenses is an operational step gated on embedding the production license
  public key (and keeping its private key offline), mirroring the update-signing key.
- Maps onto the compliance posture as an entitlement/record control once Phase 2b surfaces
  license state in the dashboard + audit log.
