# ADR-067: Release lifecycle, LTS designation & support periods

## Status

Accepted. Policy layer above [ADR-062](adr-062-air-gap-updates.md) (offline trust
foundation) and [ADR-064](adr-064-air-gap-update-bundles.md) (signed update bundles).
ADR-064 decided *how* an update crosses an air gap; this ADR decides *which* versions
get one, *for how long*, and what is promised to whom. Public expression of this
policy lives in [`SUPPORT.md`](../SUPPORT.md).

## Context

Keyorix ships from trunk. Main is linear, squash-merged, and fast: 88 tags cut to
date, ~750 commits to main in the last 30 days, median PR time-to-merge under an hour.
That cadence is an asset and this ADR does not change it.

What is missing is the lifecycle layer. Three forces make its absence a liability:

**1. Air-gapped customers cannot upgrade on our cadence.** The data-sovereignty
segment (defence, finance, government) upgrades quarterly at best, often annually,
through a change-approval process measured in weeks. A customer pinned to an old
version who hits a CVE has exactly two options: take a backported patch, or run
knowingly vulnerable. Today we can offer neither, because no maintenance line exists.

**2. The Cyber Resilience Act makes the support period a legal artifact, not a
marketing one.** Article 13(8) requires a declared support period of at least five
years unless the product is expected to be in use for less time — which a secrets
manager inside a regulated enclave is not. Each security update must remain available
for ten years after issue or the remainder of the support period, whichever is longer.
The end date (month and year) must be stated at the time of purchase.

The Commission's March 2026 draft guidance adds the sharp edge: for software that
evolves through multiple versions, **each version placed on the market is expected to
carry its own defined support period**. Read naively against 88 tags, that is 88
concurrent five-year obligations. Unmanaged, this is an existential documentation and
engineering burden for a small team.

**3. It is a competitive opening.** Vault's Community Edition receives fixes only on
the current release. HashiCorp's two-year LTS programme covers only versions released
before April 2026; later versions moved to IBM's Support Cycle-2 framework following
the acquisition. Conjur sits inside Palo Alto Networks. A published five-year support
period on an AGPL binary is a commitment none of them currently match, and after
CRA's main obligations apply it becomes something EU buyers are required to ask about.

**Open question, deliberately not resolved here.** The CRA excludes free and open
source software supplied outside commercial activity. Keyorix is AGPL-3.0 with a
private dual commercial licence. Whether our AGPL binary distribution falls inside
CRA scope is a question for counsel, not for this ADR. This ADR is written so the
answer does not change the engineering: we adopt the stricter posture regardless,
because we intend to sell the support period as a feature.

## Decision

### 1. Tagged is not "placed on the market"

We distinguish two artifact classes, and the distinction is stated on every release:

- **Development tags** — cut freely from main, as today. No Declaration of
  Conformity, no CE marking, no declared support period, no update bundle. Release
  notes carry an explicit notice to this effect.
- **Designated releases** — the only artifacts placed on the market. Each carries a
  declared support period with an end month and year, a Declaration of Conformity, a
  signed ADR-064 update bundle, an SBOM, and a VEX document.

This is the load-bearing decision. Everything else follows from it.

### 2. Lifecycle parameters

| Parameter | Decision |
|---|---|
| Trunk cadence | Unchanged — tag freely from main |
| LTS designation | One every **18–24 months** |
| Support period | **5 years, security-only**, from LTS general availability |
| Concurrent maintained lines | **Maximum 3** (N, N-1, N-2) — a hard ceiling |
| First LTS | **v1.0**, cut at first paying production deployment |
| Non-LTS designated releases | Supported until the next designated release |
| Pre-1.0 | No support period declared; stated explicitly on every release |

**Why 18–24 months and not annual.** Annual LTS against a five-year period yields
five concurrent maintenance lines at steady state. At current team size that is not
survivable, and a promise we cannot keep is worse than a shorter one we can. An
18–24-month cadence caps concurrency at three. If the ceiling is ever reached, the
correct response is to lengthen the LTS interval, never to breach the ceiling.

**Why security-only.** The CRA mandates security updates, not feature parity. An LTS
line receives fixes for vulnerabilities and outage-class defects. It does not receive
features, performance work, or cosmetic fixes. Scoping this tightly is what makes a
five-year commitment affordable; leaving it vague is what makes it ruinous.

**Why five years rather than a shorter declared period.** Five years is the Article
13(8) floor for a product of this expected lifetime, so there is little room to argue
down. It is also our strongest structural advantage over competitors who have just
lost theirs. Declaring less would concede that advantage to save effort we are
largely obliged to spend anyway.

### 3. Branch model

Maintenance lines are `release/X.Y.x`, cut at the LTS tag. They are **never merged
back into main**.

- **Fix forward first, always.** A fix lands on main, then is cherry-picked down to
  every live LTS line. Fixing on a maintenance line first is prohibited: it is the
  mechanism by which lines silently diverge from trunk.
- **Label-triggered backport.** A `backport/X.Y.x` label on a merged PR triggers an
  automated cherry-pick PR against that line. Conflicts fall back to a manual PR.
- **Full CI per line.** Every maintenance line runs the complete workflow matrix on
  every backport. A maintenance line with a weaker gate than main is not a supported
  line.
- **Additive-only migrations within an LTS line.** No column drops, no type changes,
  no destructive rewrites within a maintained major. This is the single architectural
  constraint that keeps backports cheap, and it is what makes five years tractable.
  It is a design obligation on every schema change, not a release-time concern.

### 4. Definition of done for a security fix

A security fix is not complete until **all** of the following hold:

1. Merged on main
2. Cherry-picked to every live LTS line, with CI green on each
3. Advisory published (GitHub Security Advisory + CVE where applicable)
4. **VEX document updated** and republished
5. Update bundles rebuilt and signed for each affected line (ADR-064)
6. CHANGELOG updated on main and on each affected line

### 5. VEX is mandatory, not optional

Air-gapped customers run their own scanners against our images and binaries. Those
scanners will flag CVEs in vendored Go dependencies that our code paths never reach.
Without a machine-readable VEX statement, each false positive becomes a support
conversation — the failure mode that scales worst for a small team, and one that
lands hardest precisely with the regulated customers we are courting.

We already emit CycloneDX 1.6, which carries VEX natively. VEX generation is added to
`make release` alongside SBOM generation and shipped inside the ADR-064 bundle
manifest as a pinned component.

### 6. Upgrade path guarantee

Direct upgrade from any LTS to the next LTS is supported and tested. Customers on an
LTS line never need to traverse intermediate designated releases. ADR-064's
`min_upgrade_from` manifest field is the enforcement point: it is set to the previous
LTS, not the previous release.

## Consequences

**Positive.** A published support policy is a sales artifact before it is an
engineering one — it is what procurement asks for in the first month, and it is an
answer Vault Community Edition cannot give. The three-line ceiling bounds the
maintenance burden explicitly rather than letting it grow by accident. Separating
development tags from designated releases converts a potential 88-version compliance
surface into a handful.

**Negative.** Additive-only migrations constrain schema design inside a maintained
major; some refactors must wait for the next LTS. Maintenance-line CI multiplies
runner minutes by the number of live lines. Cherry-pick conflicts will require
manual work as lines age — this is the recurring cost, and it is why the concurrency
ceiling is a hard limit rather than a target.

**Deferred.** Whether extended support beyond five years becomes a paid commercial
tier is not decided here; the policy leaves room for it. The CRA scope question for
AGPL distribution goes to counsel before any support period is formally declared.

## Follow-ups

- `SUPPORT.md` — public expression of this policy (this change)
- Pre-1.0 disclaimer wired into the release-notes template
- VEX generation in `make release` — separate ADR if the tooling choice is contested
- Backport automation workflow — deferred until the first LTS line exists
- Coordinated vulnerability disclosure runbook: the 24h/72h/14-day ENISA reporting
  chain, documented before the first commercial deployment
