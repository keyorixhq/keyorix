# ADR-068: Feature flags — no flag service, three separate mechanisms

## Status

Accepted. Constrains [ADR-065](adr-065-offline-license-validation.md) (entitlements)
and depends on the release classes defined in
[ADR-067](adr-067-release-lifecycle-support-policy.md).

## Context

Keyorix ships from trunk at high velocity — median PR time-to-merge under an hour,
~750 commits to main in a 30-day window. That cadence needs a way to merge incomplete
work without shipping it, which is the classic argument for feature flags.

The classic answer — adopt a flag platform, put everything behind it — is wrong for
this product, and wrong in ways that are expensive to undo. Three properties of
Keyorix make it so:

**Flags are effectively permanent.** In SaaS you remove a flag when the rollout
completes. On-premises, a flag shipped in a designated release lives until every
customer has upgraded off that release — which under ADR-067 can be five years. Flag
debt does not decay here; it accrues.

**The configuration space is unobservable.** No phone-home (ADR-065), no telemetry.
Air-gapped customers can run any combination of flags and we cannot see which. Every
flag multiplies a test matrix we can neither sample nor observe in the field.

**A toggle that weakens a security control is an attack surface.** This is a secrets
manager. A flag system that can disable audit logging, relax an auth check, or turn
off AAD binding is a privilege-escalation primitive wearing a product-management hat.

There is also a positioning constraint. A hosted flag SDK (LaunchDarkly and
equivalents) phones home, which contradicts the sovereignty argument the product is
built on. A self-hosted flag service (Unleash, Flagsmith) pushes an extra deployment
into the customer's enclave, and their security review will reasonably ask what that
component is and whether it can alter their security posture remotely. For a secrets
manager the only acceptable answer is that nothing can.

## Decision

**Keyorix has no feature-flag service and adds no feature-flag dependency.** What is
usually one system is split into three mechanisms with different lifetimes, different
trust properties, and different removal rules.

### 1. Release flags — build tags, or config, default off

Purpose: let incomplete work sit on main without shipping it. Temporary by
definition.

- **Compile-time (`//go:build`) is preferred** over runtime configuration. A build
  tag cannot be flipped by an attacker who obtains config write access, and it leaves
  no dead branch in the shipped binary.
- Runtime release flags, where unavoidable, are read from the config file only.
  Default is always **off**.
- **Removal deadline: one designated release.** A release flag still present in the
  second designated release after its introduction is a defect and is tracked as one.
  ADR-067's release classes exist partly to make this deadline enforceable.
- Release flags are never documented as customer-facing configuration. If a customer
  is meant to set it, it is not a release flag — it is configuration.

### 2. Operational controls — ordinary configuration, audited, fail-closed

Purpose: disable a misbehaving dynamic-secrets backend, disable an auth method under
attack, tighten rate limits. Permanent, customer-facing, part of the supported
surface.

These are **configuration, not flags**, and are documented as such. Calling them
flags implies a temporariness that would justify weaker treatment than they deserve.

Three requirements, all non-negotiable:

- **Fail closed.** Missing, malformed, or unparseable → the restrictive value, with a
  startup error where the setting is security-relevant. This extends the fail-closed
  posture already required across the auth, RBAC, and AAD paths.
- **Audited on change.** Every change to a security-relevant control emits an audit
  event carrying the actor and the before/after values. A control that can be
  silently disabled is not a control.
- **No remote toggling, ever.** Config file or environment only, applied at startup
  or by an explicit, audited reload. There is no API that changes these.

### 3. Entitlements — ADR-065 licence claims

Purpose: gate commercial features. Already built; this ADR adds one constraint.

**An entitlement may never gate a security control.** Audit logging, authentication,
authorisation, encryption, tamper evidence, and their configuration surface are
available on the AGPL build without a licence, permanently. Entitlements gate
commercial *convenience and scale* features — compliance evidence packs, extended
support — never the ability to be secure.

This is the "security is never paywalled" principle stated as an engineering rule
rather than a marketing claim. Without it, the boundary erodes one reasonable-seeming
decision at a time, and each erosion is invisible until a competitor points at it.

### 4. Experimentation flags — rejected outright

A/B testing requires telemetry. ADR-065 commits to no phone-home. There is no
experiment infrastructure, and none will be built. This is recorded explicitly so
that nobody designs toward a capability that cannot exist.

## Cross-cutting requirements

**Supported-combination policy.** Every flag or control is either in the tested CI
matrix or explicitly marked unsupported/experimental in the documentation. There is
no third category. Because the field configuration is unobservable, an untested
combination is one we will first learn about from a customer incident.

**Flags are part of the compliance posture surface.** Compliance evidence must be
generated from *actual runtime state*, not from assumed defaults. If a control can be
disabled by configuration, the evidence pack and the posture API must read the live
value. An evidence pack that asserts a control is enabled while it is off is worse
than no evidence pack: it is a false attestation, and it is the kind of defect that
surfaces during an audit rather than during testing.

**A flag is a cost, not a free option.** Each one adds a permanent branch to a test
matrix that cannot shrink on our schedule. The default answer to "should this be a
flag?" is no.

## Alternatives considered

**Hosted flag platform (LaunchDarkly and equivalents).** Rejected. Phones home, which
directly contradicts the sovereignty positioning and cannot work air-gapped at all.

**Self-hosted flag service (Unleash, Flagsmith).** Rejected. Adds a component the
customer must deploy and security-review inside their enclave, and introduces a
remote-toggle path into a secrets manager's security controls. The operational burden
lands on the customer, which is precisely the failure mode we criticise Vault for.

**OpenFeature Go SDK with a file provider.** Rejected for Keyorix, but it was close.
In favour: evaluation hooks would make audit-on-toggle nearly free, and it is the
CNCF-neutral standard. Against: a third-party dependency in an air-gapped security
product whose central argument is minimalism, in service of an abstraction we have
just decided to keep small. Consistent with `internal/trust` and `internal/bundle`,
the mechanisms above stay in-tree with no new dependency. Revisit if the number of
runtime-evaluated controls grows past the point where hand-rolled auditing is
error-prone.

## Consequences

**Positive.** No new dependency, no new customer-deployed component, no remote path
to a security control. The three-way split gives each mechanism the treatment it
deserves rather than flattening them into one abstraction with the weakest common
properties. The entitlement constraint makes the paywall boundary checkable in review.

**Negative.** Compile-time release flags mean some combinations require separate
builds, which multiplies release artifacts. Without a flag service there is no
percentage rollout and no remote kill switch — a bad release must be fixed by
shipping a new one, which under air-gap timelines is slow. That is an accepted cost:
the alternative is a remote control channel into a secrets manager.

**Deferred.** DashDiag's flag strategy is explicitly *not* decided by this ADR.
As a SaaS product it inverts nearly every constraint here and should adopt
OpenFeature with a self-hosted provider — but not before its cloud backend exists.

## Follow-ups

- Audit existing config for security-relevant settings that are not fail-closed
- Verify the compliance posture and evidence-pack code reads live control state
  rather than assumed defaults
- Add a release-flag inventory to the release checklist, with the one-release
  removal deadline enforced at designation time
