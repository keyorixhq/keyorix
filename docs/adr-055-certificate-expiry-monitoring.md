# ADR-055: Certificate-expiry monitoring

## Status

Accepted.

## Context

Certificate inspection (ADR-054) lets an operator *ask* for a certificate's real
`notAfter`, but answering "which of my certificates are about to expire?" still required
checking each one by hand. An expired TLS certificate that nobody noticed is a classic
cause of production outages, and certificate hygiene is an availability/continuity
control under NIS2 and ENS. Keyorix already has a secret-expiry reminder scheduler, but
it keys off the manually-set `Expiration` field — which certificate secrets usually
leave unset, relying on the cert's own validity window. So certs fell through the gap.

## Decision

Add an opt-in **certificate-expiry scan** that proactively notifies project admins of
certificates that are expired or expiring within a lead window, using the certificate's
*real* `notAfter`.

- **Scan.** `ScanCertificateExpiry(leadDays)` lists certificate-typed secrets, parses
  each leaf certificate (reusing the ADR-054 parser), and for those whose `notAfter` is
  before `now + leadDays` tallies expired vs. expiring-soon per project. It sends ONE
  standing digest notification (`secret.certificate_expiry`) to each affected project's
  approver-role members, de-duplicated against an existing unread reminder — exactly the
  mechanism the secret-expiry reminder uses.
- **Scheduler.** Opt-in `certificate_expiry` config block (`enabled`, `schedule`,
  `lead_days`; default off, 24h interval, 30-day lead — wider than generic secrets since
  certs take longer to re-issue). Runs in the single-replica-gated scheduler (ADR-039).
- **Value handling.** The scan decrypts certificate-typed secret values to read
  `notAfter`. It reads off the **non-`max_reads`-counting** path (a system scan is not a
  user value read), respects suspension (a suspended secret is skipped), and never
  returns or exposes the value or any private key — only the expiry time is used, and
  only the per-project counts reach the notification. An unparseable value is skipped,
  not an error.

## Alternatives considered

- **Extend the existing secret-expiry reminder to be cert-aware.** Cleaner (no new
  scheduler) but changes the behaviour of an already-shipped opt-in feature and couples
  cert decryption into it. A separate, independently opt-in scan keeps the concern
  isolated and the change additive.
- **Cache the parsed `notAfter` at write/inspect time and scan the cache (no repeated
  decrypt).** Architecturally tidy and avoids decrypting on every tick, but only covers
  certs created/rotated/inspected after the change (a backfill gap) and adds persisted
  state. Deferred — the scan-and-parse approach works for every certificate immediately;
  caching is a reasonable later optimisation if scan cost becomes a concern at scale.
- **On-demand fleet report instead of a scheduler.** Useful, but it still requires an
  operator to look; proactive notification is the point (prevent the silent lapse).

## Deferred follow-ups

- Cache `notAfter` (and issuer) on the secret to avoid per-scan decryption at scale, and
  surface it in the expiry/rotation posture and dashboards.
- Full-chain expiry (intermediates), and per-environment / deployment-wide scopes.
- External delivery (email/webhook) of the digest via the existing notifications fan-out.
