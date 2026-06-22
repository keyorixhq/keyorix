# ADR-054: Certificate inspection

## Status

Accepted.

## Context

A large share of stored secrets are X.509 certificates (TLS certs, CA chains). Keyorix
tracks a manually-set `Expiration` on a secret, but for a certificate the *real* expiry
is `notAfter` inside the certificate itself — which Keyorix never looked at. Operators
had no way to see a certificate's actual validity window, issuer, or SANs without
exporting the value and running `openssl` by hand. Certificate hygiene (knowing what
expires when, who issued it) is a concrete control under ENS (`mp.info`/`op.exp`) and
NIS2.

## Decision

Add **certificate inspection**: `InspectCertificate(secretID)` parses the leaf X.509
certificate from a secret's value and returns its **public metadata** — subject,
issuer, serial, `notBefore`/`notAfter`, days-until-expiry, is-expired, is-CA,
self-signed, SANs, signature & public-key algorithms. Exposed at
`GET /api/v1/secrets/{id}/certificate` (scoped `secrets.read`) and
`keyorix secret cert <id>`.

The deliberate constraints:

- **Public metadata only — never the value or any private key.** The parser only ever
  reads `CERTIFICATE` PEM blocks; a bundled `PRIVATE KEY` block is ignored. The
  response struct has no field that could carry the value or key material. So a caller
  who can already `secrets.read`/reveal the secret learns nothing they couldn't already
  obtain — inspection just parses the public part for them.
- **Does NOT count against `max_reads`.** Reading a certificate's public metadata is not
  value consumption, so inspection decrypts via the *non-counting* sibling of the value-
  read path. A one-time-read certificate is not "spent" by inspecting its expiry. (This
  is the one place that decrypts a value off the counting path — justified because
  nothing secret leaves the boundary.)
- **Respects suspension.** A suspended secret (frozen for incident response) is not
  decrypted/inspected. Expired secrets *are* inspectable — seeing why is the point.
- **Audited.** Every inspection writes `secret.certificate_inspected` (actor + secret +
  issuer + expiry), so the access is on the trail like any value-adjacent read.
- **Authorization** is scoped `secrets.read` (environment-granular), enforced at the
  transport layer — the same gate as the other *value-derived* read endpoints
  (`/{id}/risk`, `/{id}/impact`). This is deliberately the route-scope gate and **not**
  the stricter per-user owner/share check the full-value reveal applies: a project
  auditor or reader should be able to see certificate hygiene (what expires when)
  without being a share-recipient of every secret. The exposed fields are the public
  part of the certificate that any TLS client already sees, so this is not a new
  exposure of secret material.

## Alternatives considered

- **Parse at write time and store cert metadata as fields.** Avoids decrypting on read,
  but only covers certs created/rotated after the change (a backfill gap), complicates
  the create/rotate path, and duplicates state that can be derived. Read-time inspection
  works for every existing certificate immediately. Persisting parsed expiry as a
  posture signal is a reasonable later addition on top of this.
- **Count inspection against `max_reads`.** Rejected — it would let "check the expiry"
  silently consume a one-time secret, which is surprising and wrong; the metadata is not
  the secret.
- **Return the full certificate PEM.** Unnecessary — the caller can already reveal the
  value through the normal path; inspection's value is the *parsed* public fields.

## Deferred follow-ups

- Surface certificate `notAfter` in the expiry/rotation posture and dashboards (use the
  real cert expiry, not just the manual field), and flag soon-expiring certs.
- Full chain inspection (intermediates) and chain-validity, not just the leaf.
- gRPC surface and a keyorix-web certificate panel on the secret detail page.
