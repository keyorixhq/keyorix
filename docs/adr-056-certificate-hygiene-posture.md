# ADR-056: Certificate hygiene in the compliance posture

## Status

Accepted.

## Context

Certificate inspection (ADR-054) and the expiry scan (ADR-055) read a certificate's
real `notAfter`, but the **compliance posture / control matrix** — the auditor-facing
view (ISO 27001 / SOC 2 / NIS2 / DORA / ENS) — had no signal for certificate hygiene.
An expired TLS certificate is both an availability incident and a control gap (ENS
`op.exp.11`, NIS2 Art.21). The obstacle: the posture is computed on a hot, frequently
polled path (the compliance dashboard), so it must not decrypt every certificate on
each view; and threading certificate parsing into the create/rotate write path would be
a sensitive change with a backfill gap.

## Decision

Add a **Certificate expiry hygiene** control and a `CertificatePosture` figure, fed by a
**cached** certificate expiry maintained off the read path.

- **Cache.** `SecretNode.CertNotAfter` (additive, nullable column) caches the parsed
  leaf-certificate `notAfter`. It is populated **as a side-effect** of the two paths
  that already decrypt and parse a certificate — `InspectCertificate` (ADR-054) and the
  certificate-expiry scan (ADR-055) — via a targeted single-column update. Nothing else
  writes it; the create/rotate path is untouched.
- **Posture.** `certificatePosture` counts certificate-typed secrets by their *cached*
  `CertNotAfter` (expired / expiring-soon / total / **not-yet-evaluated**) — a plain
  column read, no decryption. It is wired into `GetCompliancePosture`.
- **Control.** A `certificate-hygiene` control in the matrix: a **gap** when any
  certificate is expired, with a detail line that also surfaces expiring-soon and
  not-yet-evaluated counts. Mapped to ISO 27001 A.5.15/A.8.24, SOC 2 CC6.1, NIS2
  Art.21(2)(h), ENS `op.exp.11`.
- **Coverage.** A certificate that has never been inspected or scanned has a nil cache
  and is reported as **not yet evaluated** (honestly, not silently "healthy"). Full
  coverage comes from enabling the ADR-055 certificate-expiry scan, which refreshes the
  cache for every certificate on each run — so a rotated certificate's cache self-heals
  on the next scan without any write-path coupling.

## Alternatives considered

- **Parse at create/rotate and store the expiry there.** Avoids relying on the scan for
  coverage, but touches the sensitive write path and still needs a backfill for existing
  certs. The scan-maintained cache keeps the write path untouched and backfills every
  certificate on its first run.
- **Decrypt-and-count on the posture path.** Simple, but decrypting every certificate on
  each dashboard poll is exactly what the cache avoids.
- **A separate certificate report instead of a posture control.** The control matrix is
  where auditors look; a first-class control is higher leverage than a side report.

## Deferred follow-ups

- Invalidate/refresh the cache on rotation immediately (rather than on the next scan).
- Surface the not-yet-evaluated count in the dashboard with a prompt to enable the scan.
- Per-environment certificate posture; full-chain (intermediate) expiry.
