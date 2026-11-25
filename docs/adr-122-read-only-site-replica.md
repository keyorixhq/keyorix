# ADR-122: Read-only site replica for disconnected sites (leaf node)

**Status:** Proposed (2026-11-25). Preliminary: recorded so the evidence is not lost. Not accepted
until Andrei approves, and the reopening trigger below is not met. No code follows from this ADR.
**Date:** 2026-11-25
**Origin:** Follow-up interview with the author of the 2026-11-21 devops.org.ru review (an
infrastructure lead who runs Vault). Notes: a private Keyorix planning note dated 2026-11-25
(follow-up interview), kept outside this repository; the facts this ADR relies on are restated
in Context below so the ADR can be read without it.

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

A second remark from the same evaluator is a requirement on the design, not on a site: horizontal scaling of the centre is mandatory, and the nodes must not be synchronised through a key-value store of the etcd kind. His reason is experience: a split brain when one data centre drops, then a hard recovery. Recorded as input from one voice, like the rest.

**Reopening trigger:** two or more prospects who need central management of disconnected
sites. Until then no implementation work starts. No website claim of edge or IoT readiness
(the "Edge & IoT ready" wording, removed earlier; the decision is recorded in the planning
notes, not in this repository) is made until the capability exists and is benchmarked.

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
   Two kinds of record must not be mixed up. **Audit records** are hash-chained evidence
   (ADR-029); each site keeps its own chain, and the centre treats a copy as reported by the
   site (point 7), not as a replacement for the site's chain. **Operational logs** are not
   replicated by Keyorix at all: they go to the customer's own log stack (ELK, Loki), which a
   large technology company already runs. The evaluator's view: logs in large companies should
   reach ELK or Loki by themselves. For audit, main already has native push to a SIEM
   (`audit.siem`: `splunk`, `datadog` or generic `webhook`) with an optional on-disk spool
   that re-sends until the receiver accepts, so a site can deliver its audit to the
   customer's SIEM when the link returns. There is no native Loki or Elasticsearch provider;
   whether the generic `webhook` fits them is unchecked. Centre-side collection of site audit
   is therefore optional, and the fleet view (point 5) stays status only.
3. **Service identity on a site.** Machine-identity OIDC federation needs a reachable issuer.
   Verification from a local key file with no reachable issuer is not supported on main.
   [ADR-075](adr-075-airgap-oidc-federation.md) (Proposed) covers air-gapped OIDC with an
   internal IdP, which is only a loose match: a site needs a locally verifiable identity path,
   and whether ADR-075 can be extended to it is open.
4. **Rotation with lag.** If the centre rotates while a site is offline, the old credential must
   stay valid until every site has acknowledged the new one. Overlapping validity of an old and a
   new credential is not implemented today: [ADR-035](adr-035-dynamic-secrets.md) (related, not
   reused) issues a single short-lived credential per lease and revokes it at expiry. A
   dual-validity rotation scheme is a new design item for this ADR or a follow-up.
5. **Fleet view in the centre.** Per site: last seen, version of each replicated secret,
   rotation pending or acknowledged. Sites report status only, never values. This slice can ship
   before replication exists and is the part the evaluator named as decisive.
6. **Stolen gateway and revocation lag.** Replicate only that site's secrets, never the whole
   store. One central command revokes a site. A revoked site can still serve its cached secrets
   until it next reaches the centre or its lease on the replica expires; the maximum offline
   lease must be an explicit, per-site setting, with the default fail-closed.
7. **Site-originated data is untrusted.** The only things a site sends to the centre are its
   status and its audit records. The centre treats both as input from an unknown box: it
   authenticates the site, validates the shape, never lets them change a secret, a policy or
   another site's state, and shows them as "reported by the site", not as verified fact. The
   evaluator's reason for the one-way model is exactly this: nobody knows where the box stands
   or who has touched it.
8. **Replication mechanism.** See the next section.

## Replication mechanism (open)

The evaluator confirmed that one-way replication is simpler to build and safer than two-way,
because the state of a remote box cannot be trusted. He added that if it is built, it should use
a proven resilient mechanism, naming block-level replication or Raft, and said Raft has a good
record. His remark is recorded as input, not as a decision. Requirements the mechanism must meet,
taken from the points above:

- A site receives only its own subset of secrets, never the whole store (point 6).
- The site starts the connection and the centre needs no inbound path (model above).
- It tolerates links that are down for hours, resumes where it stopped, and applying a batch
  twice changes nothing.
- It runs on SQLite on a small gateway and does not turn Keyorix into a different storage engine.
- What the site holds is re-encrypted for that site, so a copy of the site's data does not
  expose the centre's keys.

Options, to be tested against those requirements before choosing:

| Option | Fit | Concern |
|---|---|---|
| One-way change feed built in Keyorix: the single writer numbers every change to a site's subset, the site pulls batches after its last acknowledged number, applies them idempotently, and acknowledges | Meets all five requirements; no election or quorum is needed because there is one writer | The code is ours to write and prove; needs the fault-injection tests the project already uses for storage |
| Raft, with the site as a non-voting follower | Mature, well understood; lag of a follower does not affect the centre | One log carries everything to every follower, so there is no per-site subset unless there is one log per site (fifty groups at the centre); it replaces the storage layer rather than sitting on SQLite or PostgreSQL; its main gain, failover of the writer, is a different problem from centre-to-site replication |
| Block-level replication of the database | Simple to describe | Copies the whole encrypted store under the same keys, which breaks the subset and re-encryption requirements; replicates corruption and tampering as faithfully as data |
| PostgreSQL logical replication | Native, row filters exist in recent versions | Sites run SQLite; ties the site to PostgreSQL |

Centre availability (several central nodes, failover of the writer) is a separate question from
this ADR, but the evaluator's requirement above constrains how it may be answered. What exists
today (ADR-039, Accepted): several identical stateless API replicas behind a load balancer, all
using one PostgreSQL; the audit chain and the background schedulers are serialised with
PostgreSQL advisory locks; there is no node-to-node synchronisation and no consensus store in
Keyorix. That design has no split brain of its own, because there is one writer, the database.
It moves the question to the operator's PostgreSQL high availability, which Keyorix does not
provide and does not describe for a multi-data-centre case; known caveats are in ADR-039 (login
rate limit counted per replica, schema-epoch rolling upgrade gap). Whether the multi-replica
behaviour holds under test has not been verified for this ADR. Rule for any later design of the
centre: no consensus or key-value store added to the secrets path, and one writer at any moment
(the same shape as the one-way change feed above, which also has one writer by construction).
Raft or similar stays a candidate only if it is shown not to bring that failure mode back.

The statements about Raft and PostgreSQL in the table are general knowledge and must be verified
against current documentation before this ADR is accepted.

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
How many data centres, where the Vault database sits today, and what exactly was hard in recovery after a split brain.

## Consequences

Nothing changes in the product today. If accepted later, this adds a sync protocol, a
status-reporting API, a per-site replica scope and an offline-lease setting, and it depends on
the unseal and offline-identity decisions above. Each of those needs its own ADR or amendment
before code.
