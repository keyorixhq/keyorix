# Keyorix Licensing

Keyorix is dual-licensed. This document explains the model and the principles
behind it — and commits us to them publicly.

## The model

- **Open source:** everything in this repository is licensed under
  **AGPL-3.0** (see [LICENSE](LICENSE)). All of it. Every feature — encryption,
  RBAC, audit logging, MFA and passkeys, OIDC federation, dynamic secrets,
  high availability, anomaly detection, SIEM export — is in the open codebase.
  There is no enterprise directory, no licence-gated code path, and no
  feature flag that checks who you are.
- **Commercial:** organizations that cannot or prefer not to operate under
  AGPL terms can license the same software under a private commercial
  agreement, which additionally provides warranties, indemnification,
  support with SLAs, security-fix backports, and compliance reporting
  tooling. Contact **hello@keyorix.com**.

## Our principles

**1. Security is never paywalled.** Anything that protects you — audit data
and its retention, the query API, SIEM export, MFA, anomaly detection — is
free, complete, and uncapped in the open edition, forever. Commercial
offerings sell convenience and accountability (support, legal terms,
packaged compliance reports), never protection.

**2. What's open stays open.** We will not relicense existing open code under
a more restrictive licence, and we will not move features that have shipped
under AGPL behind a paywall. Future *commercial-only* products may exist
(built as separate tools that were never part of the open codebase), but
nothing released here will ever be taken back.

**3. Your deployment owes us nothing — not even a network packet.** The
software sends no telemetry, no usage metering, and no licence checks to us.
Commercial licence enforcement is a signed file your server validates
locally. An expired licence warns; it never disables a running secrets
manager.

## Trademark

"Keyorix" is a trademark of Keyorix SL. The AGPL licence covers the code,
not the name: you may use, modify, and redistribute the code under AGPL
terms, but distributing modified versions or commercial offerings under the
Keyorix name requires our written agreement. A full trademark policy will be
published here.

## Contributing

Contributions require a signed Contributor License Agreement (CLA), which is
what allows us to sustain this dual-licensing model. Your contribution stays
AGPL-licensed in this repository under principle 2, always.

---

*Questions about licensing, commercial terms, or the design partner program:
**hello@keyorix.com***
