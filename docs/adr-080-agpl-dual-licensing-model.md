# ADR-080: AGPL-3.0 dual-licensing model

## Status

Accepted, as-built. Backfill ADR — the licensing model was ratified June 12, 2026
(recorded in the private strategy doc, not previously as a public-repo ADR) and has
been the standing model since. Recorded now per the M2 "ADR backfill" backlog item.
See ADR-065 for the offline license-validation *mechanism* this ADR's commercial
tier relies on — this ADR covers the business/licensing *model* decision itself,
not the technical enforcement.

## Context

Keyorix needed a licensing model that satisfies three simultaneous, partly-tense
goals: be genuinely open source (not open-core-with-a-locked-`ee/`-directory,
which is Keyorix's own stated competitive line against Infisical's
audit-logs-paywalled-on-self-hosted positioning); have a real path to commercial
revenue without engineering an ongoing feature-gate maintenance burden a solo
founder can't sustain; and give enterprise legal teams — the actual buyer, in a
security-tooling category — a way to adopt the product without a viral-copyleft
review blocking the deal.

Options considered (recorded in the private strategy doc; summarized here since
that document isn't part of the public repo):

- **MIT/Apache-2.0** — permissive. Rejected: no leverage for a commercial tier;
  nothing stops a cloud provider from re-hosting the product as a competing managed
  service with zero obligation back to the project.
- **Business Source License (BSL)** — time-delayed open source, HashiCorp's chosen
  model. Rejected: not OSI-approved, which some enterprise legal teams reject
  outright regardless of the specific terms; and the 2023 HashiCorp BSL backlash
  (Terraform → OpenTofu fork) is treated as *Keyorix's* recruiting and community
  opportunity — positioning as "the open one" relative to a HashiCorp-alumni
  audience specifically, rather than repeating HashiCorp's own move.
- **Open core** (permissive core + proprietary `ee/` add-ons) — the Infisical/most
  common competitor model. Rejected on two grounds: it requires an ongoing
  feature-gate engineering discipline (deciding, for every new feature, which side
  of the line it falls on, and maintaining that boundary in code) that doesn't fit
  a solo-founder engineering capacity; and it directly undercuts the competitive
  claim that security capability itself should never be paywalled.
- **AGPL-3.0 core + private commercial license** — the adopted model, detailed
  below.

## Decision

**The entire repository is licensed AGPL-3.0** (`LICENSE`, full GNU AGPLv3 text;
`COPYRIGHT` adds a "Network Copyleft Notice" explaining the SaaS-loophole closure
AGPL provides over plain GPL — running a modified version as a network service
counts as distribution, triggering the source-disclosure obligation). There is no
`ee/` directory, no license-gated *security* feature, and no code path that
behaves differently based on who is running it, for anything security-relevant.
This is stated as a standing principle in `LICENSING.md`: "Security is never
paywalled."

**Two features are commercially gated**, and only two — deliberately narrow, and
both non-security: `internal/license/features.go` defines exactly
`FeatureAirgapUpdates` ("airgap_updates", gating `keyorix bundle import`) and
`FeatureBilling` ("billing", gating the FinOps billing report). `Gate.HasFeature`
fails safe — a nil `*Gate` (no license installed) returns the community baseline,
never a hard failure. This is intentionally the inverse failure direction from the
update-bundle *signature* verification (which fails closed, per ADR-062/064) — a
missing or invalid commercial license degrades functionality, it never bricks a
deployment or blocks access to already-stored data.

**Organizations that cannot or prefer not to operate under AGPL terms** — the
actual target of the commercial tier — can license the same code under a private
bilateral commercial agreement (MSA + Order Form, not a second source-available
license like BSL or Elastic's). The commercial license's substantive offering is
*removal of AGPL's obligations*, plus a warranty and IP indemnity AGPL doesn't
provide — the Grafana/MinIO/pre-SSPL-MongoDB model. Structure: annual subscription
with a perpetual fallback, self-certified node counts, an offline signed license
file (ADR-065's mechanism) that never phones home.

**The redistribution guard is trademark, not license terms.** AGPL's copyleft
covers the *code* — anyone may fork, modify, and redistribute it under AGPL. What
AGPL doesn't prevent is a third party redistributing a modified fork *under the
Keyorix name*, implying an affiliation or quality bar that doesn't exist.
`LICENSING.md` states this directly: "'Keyorix' is a trademark of Keyorix SL... The
AGPL licence covers the code, not the name... distributing modified versions or
commercial offerings under the Keyorix name requires our written agreement."
Trademark registration itself (EUIPO, classes 9/42) remains an open backlog item as
of this writing — the *policy* is decided and documented; the registration filing
is a separate, still-pending action tracked in the private backlog, not blocked on
this ADR.

**Contributor terms.** `CONTRIBUTING.md` requires DCO sign-off (enforced in CI, per
this repo's own commit conventions) on every commit — "your contribution will be
under the same license" (AGPL-3.0). `LICENSING.md` separately references a signed
CLA. These are two different mechanisms (DCO is a per-commit attestation; a CLA is
a separate signed agreement) stated in two different documents — worth reconciling
into one contributor-terms story in a future doc pass, noted here rather than
silently left inconsistent.

## Consequences

- **Positive.** The "security paywalled on self-hosted" competitive line against
  open-core competitors holds structurally, not just as marketing copy — there is
  no code path to audit that contradicts it, because the gate only ever checks two
  named non-security features. Feature development doesn't carry an ongoing
  "which license tier does this belong to" tax, since the default for every new
  feature is simply AGPL/open unless a maintainer deliberately adds it to
  `features.go`.
- **Negative / accepted tradeoff.** AGPL is a real adoption friction for exactly
  the population (enterprise legal, regulated sectors) the product also needs as
  customers — but that friction is the intended mechanism, not a side effect: it's
  what makes the commercial license a genuine choice rather than a redundant
  upsell on top of an already-permissive license.
- Trademark registration is a genuine open action item (tracked in the private
  backlog), not yet filed as of this ADR — the policy `LICENSING.md` states is
  ahead of the legal registration that would make it enforceable. Flagged here so
  it isn't mistaken for already-complete because the policy document exists.
