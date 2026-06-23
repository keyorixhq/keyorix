# ADR-063: SAML 2.0 SSO (Service Provider)

## Status

Accepted (design). Implementation phased; see [saml-sso-design.md](saml-sso-design.md).

## Context

Keyorix federates human logins via **OIDC** and machine identities via OIDC (ADR-031), but
many enterprise and public-sector identity estates still standardise on **SAML 2.0** (ADFS,
Shibboleth, older Okta/Azure AD, government IdPs). Without a SAML Service Provider, those
tenants cannot connect Keyorix to their IdP — a procurement blocker. The
post-authentication half (JIT provisioning, group→role mapping, session issuance) already
exists and is identity-source-agnostic; SAML only needs to produce the same
`(subject, email, name, groups)` from a signed assertion.

## Decision

Add a SAML 2.0 **Service Provider** as a second **SSO provider type**, reusing the existing
provisioning and role-mapping path.

- **Generalise the provider abstraction.** `SSOProvider` gains a `Type` (`oidc` | `saml`);
  the shared provisioning fields (`AutoProvision`, `DefaultRole`, `GroupSync`,
  `GroupRoleMap`) are reused verbatim, with type-specific config in their own blocks. The
  SAML flow ends by calling the same `provisionSSOUser` / `syncSSOGroups` / `syncSSORoles`
  / session-issuance code as OIDC — group→role mapping maps SAML attribute values exactly
  as it maps OIDC claim values today.
- **SP-initiated flow** with metadata, login (AuthnRequest), and ACS routes
  (`/auth/saml/{provider}/{metadata,login,acs}`), reusing the `SSOLoginState` table for
  `InResponseTo` / `RelayState`.
- **Use a vetted XML-DSig library, never hand-roll.** SAML signature validation is a
  notorious source of critical vulnerabilities (XML signature wrapping, C14N mismatches).
  Adopt `crewjam/saml` + `russellhaering/goxmldsig` (the de-facto Go SAML stack), pinned
  per SSDLC. This deliberately contrasts with the air-gap trust foundation (ADR-062), where
  hand-rolling `ed25519` over a fixed byte string is safe and correct — XML-DSig is not.
- **Safe by construction.** Mandatory signature validation against the **pinned IdP
  certificate** (never a cert from the Response), `AudienceRestriction` = SP entityID,
  `Recipient` = ACS URL, `NotBefore`/`NotOnOrAfter` with clock skew, `InResponseTo`
  matching, and one-time-use replay protection. **IdP-initiated SSO is off by default**
  (it loses `InResponseTo`); opt-in per provider only.

## Alternatives considered

- **Hand-roll SAML/XML-DSig.** Rejected: the attack surface (signature wrapping,
  canonicalization, unsigned-assertion confusion) is too dangerous to implement bespoke;
  the dependency is the safer choice.
- **A parallel SAML auth stack** separate from SSO. Rejected: duplicates provisioning,
  group/role mapping, session issuance, and audit. SAML is a provider *type*, not a new
  stack.
- **OIDC-only, tell SAML customers to bridge via an OIDC shim.** Rejected: a SAML→OIDC
  proxy is operational burden the buyer won't accept; native SAML is the procurement ask.
- **Keyorix as a SAML IdP.** Out of scope: Keyorix consumes identity, it is not an
  identity provider.

## Consequences

- A new vetted SAML dependency enters the server module (pinned, advisory-tracked).
- SAML logins are first-class: same sessions, JIT provisioning, group→role mapping, audit,
  and per-project MFA as OIDC — no new authorization surface.
- Removes an onboarding blocker for regulated/legacy-IdP tenants; maps to NIS2/DORA/ISO
  27001 (A.5.16/A.8.5)/ENS access-control controls.
- Delivery is phased (SP core → hardening/encrypted/IdP-initiated → admin ops), each phase
  its own ADR; SSO stays opt-in and config-driven, so default behaviour is unchanged.
