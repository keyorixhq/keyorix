# ADR-122: Read-only site replica for disconnected sites (leaf node)

**Status:** Proposed (2026-11-25). Preliminary: recorded so the evidence is not lost. Not accepted
until Andrei approves, and the reopening trigger below is not met. No code follows from this ADR.
**Date:** 2026-11-25
**Origin:** Follow-up interview with the author of the 2026-11-21 devops.org.ru review (an
infrastructure lead who runs Vault). Notes: Keyorix planning notes,
`claude/2026-11-25-friend-cto-interview-requests-and-next-steps.md`.

## Non-negotiable invariants this ADR must not weaken

- **Audit-before-disclosure** ([ADR-115](adr-115-local-audit-journal.md) states it): a secret value
  is never returned before its audit record is durable. A site must meet this on its own, with no
  link to the centre.
- **Authorization is not widened.** `core.Authorize` stays the only place that grants access.
- **Fail closed.** A site that cannot prove its state refuses; there is no weaker-fallback switch.
- **Immediate revocation (#G18)** is stated per replica. A site that is offline cannot honour it;
  this ADR must say so plainly and bound the gap (see point 6), not hide it.

## Context

Keyorix is built for on-premise and air-gapped deployments, but every deployment today is one
logical store. Nothing lets a central installation manage many sites that lose their link.

One evaluator described the case unprompted: a remote site where several services use a local
database and message broker, the link to the centre drops, the nearest administrator is three
hours away, and everything must come back by itself after a power cut. He would consider Keyorix
with SQLite on the site gateway, per site and not per sensor. What would decide a roll-out to
fifty branches is a central view of which sites have already rotated a password and which still
wait for connectivity.

Asked whether the model is "only the centre can change secrets, sites receive them and nobody
edits on a site", similar to an Active Directory read-only domain controller, he answered
"rather yes", because he would not trust branches given possible link loss. He called it one of
the possible variants, not a requirement. He also noted that fibre outages are now repaired
within about an hour, so the offline window is hours, not weeks.

## Evidence level, stated honestly

One voice. He is an evaluator, not a prospect, and he tested v0.96.3 on an empty stand; the
site scenario is his pilot idea, not something he ran. This ADR therefore records a hypothesis
and its design constraints.

**Reopening trigger (unchanged from the earlier deferral):** two or more prospects who need
central management of disconnected sites. Until then no implementation work starts. The website
claim "Edge & IoT ready" stays removed until the capability exists and is benchmarked.

## Proposed model (hypothesis)

- **One writer.** Only the centre creates, changes and rotates secrets. A site holds a read-only
  encrypted replica of a named subset of secrets and serves reads to local services.
- **No local edits.** A site has no write path for secret values, so a stolen or tampered
  gateway cannot become a source of truth.
- **Pull, outbound only.** The site initiates sync to the centre when a link exists, so branch
  firewalls need no inbound rule.
- **Per site, not per device.** The unit is a gateway or small server running the existing
  single binary with SQLite.

## Design points to settle (open)

1. **Restart after a power cut with no link.** The site must unseal its replica alone, and the
   key cannot sit next to the data. Candidates: a TPM-sealed key
   ([ADR-117](adr-117-tpm-sealed-kek-pcr-policy-recovery.md), Proposed, fail-closed) or a key
   issued by the centre in advance. The second is weaker if the gateway is stolen. Choice depends
   on the threat the customer cares about.
2. **Audit offline.** Write to a local durable journal first, forward to the centre on
   reconnect, so the centre sees delay, not a gap. Reuses the idea of
   [ADR-115](adr-115-local-audit-journal.md) (currently Parked); its status must be revisited.
3. **Service identity on a site.** Machine-identity OIDC federation needs a reachable issuer.
   The offline variant (verification from a local key file, no reachable issuer) is not
   supported on main; [ADR-075](adr-075-airgap-oidc-federation.md) is Proposed. A site needs a
   locally verifiable identity path.
4. **Rotation with lag.** If the centre rotates while a site is offline, the old credential must
   stay valid until every site has acknowledged the new one. The two-credential approach used for
   dynamic secrets ([ADR-035](adr-035-dynamic-secrets.md)) is the starting point.
5. **Fleet view in the centre.** Per site: last seen, version of each replicated secret,
   rotation pending or acknowledged. Sites report status only, never values. This slice can ship
   before replication exists and is the part the evaluator named as decisive.
6. **Stolen gateway and revocation lag.** Replicate only that site's secrets, never the whole
   store. One central command revokes a site. A revoked site can still serve its cached secrets
   until it next reaches the centre or its lease on the replica expires; the maximum offline
   lease must be an explicit, per-site setting, with the default fail-closed.

## Alternatives not chosen (so far)

- **Central only, sites call home.** Fails the stated requirement: services must start with no
  link.
- **Independent Keyorix per site, managed by hand.** This is today's behaviour and is what the
  fleet view is meant to replace; no central rotation visibility.
- **Multi-writer replication between sites.** Rejected for the first version: conflict
  resolution and a larger attack surface, for a need nobody has stated.

## Questions for the evaluator (open)

Fields needed on the fleet view; whether the centre must also push rotations when the link
returns or only observe; sites and services per site, local database and broker; secrets per
site and rotation frequency; who restores the gateway after a power cut and where its unseal key
should live; permission to use the "site three hours away" example (unnamed) in scenario text.

## Consequences

Nothing changes in the product today. If accepted later, this adds a sync protocol, a
status-reporting API, a per-site replica scope and an offline-lease setting, and it depends on
the unseal and offline-identity decisions above. Each of those needs its own ADR or amendment
before code.
