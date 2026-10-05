# Threat Model: Authentication (sessions, PAT, machine identity, MFA, WebAuthn, OIDC, SAML)

> Part of [`docs/security/threat-models/`](README.md). Derived from
> [`../threat-model.md`](../threat-model.md) (trust boundaries B3/B5) and
> [`../architecture.md`](../architecture.md) §4 — see those for the
> broader system view; this document narrows to the authentication
> mechanisms themselves.

## 1. System context

Nine distinct authentication mechanisms converge on the same
authorization chokepoint ([server-api.md](server-api.md)) once a caller
is authenticated — none of them grant any authority by themselves beyond
establishing *who* is calling.

```mermaid
flowchart TB
    subgraph Credentials
        PW[Password + session]
        PAT[Personal Access Token]
        MID[Machine identity token]
        OIDC[OIDC id_token\n(human or machine)]
        SAML[SAML assertion]
        TOTP[TOTP code]
        WA[WebAuthn assertion]
        REC[Recovery key\n(local only)]
    end

    subgraph Verify["Verification (per mechanism)"]
        SESSV[Session: hash lookup,\nabsolute TTL ceiling]
        PATV[PAT: hash lookup,\nrestriction filter]
        MIDV[Machine identity:\nlifecycle state check]
        OIDCV[OIDC: issuer allowlist →\nasymmetric-alg-only → jwks → aud/exp/nbf]
        SAMLV[SAML: pinned IdP cert →\nsig validation → Audience/Recipient/NotOnOrAfter → anti-replay]
        MFAV[MFA: TOTP window /\nWebAuthn origin+signature]
        RECV[Recovery: SHA-256 verifier\ncompare, local subcommand only]
    end

    IDENTITY[Authenticated principal\n+ actor_type]
    AUTHZ[core.Authorize\n(server-api.md)]

    PW --> SESSV
    PAT --> PATV
    MID --> MIDV
    OIDC --> OIDCV
    SAML --> SAMLV
    TOTP --> MFAV
    WA --> MFAV
    REC --> RECV

    SESSV --> IDENTITY
    PATV --> IDENTITY
    MIDV --> IDENTITY
    OIDCV --> IDENTITY
    SAMLV --> IDENTITY
    RECV -. local admin\nrecovery only .-> IDENTITY
    IDENTITY --> MFAV
    MFAV --> AUTHZ
```

## 2. Trust boundaries

| Boundary | Enforcement chokepoint |
|---|---|
| B3/B4 — session/PAT/machine-token validation | Same HTTP middleware + `core.Authorize` as any client |
| B5 — web UI session delivery | `HttpOnly`/`Secure`/`SameSite=Lax` cookie, never `localStorage` |
| B7 (identity-provider federation) — OIDC/SAML signing-key trust | Issuer/cert pinning checked before key retrieval |
| B8 — emergency admin recovery | Local-only subcommand, never a network endpoint (ADR-108 decision B) |

## 3. STRIDE per mechanism

- **Sessions — Spoofing/tampering.** Short-TTL access token plus a hard
  absolute lifetime ceiling refresh cannot extend; individually
  listable/revocable; delivered only via an `HttpOnly`/`Secure`/
  `SameSite=Lax` cookie. *Residual*: ~30s authentication cache window
  (revoked token/suspended account can remain valid up to the cache TTL;
  logout and password-change evict immediately).
- **PAT — Elevation of privilege.** SHA-256-hashed at rest; optionally
  restricted at creation to a permission allowlist and/or a single
  project scope — a filter that only ever narrows below the owner,
  enforced at the same chokepoint as every other authorization decision,
  before role resolution and before the admin bypass (ADR-027, ADR-042).
  Metamorphic-fuzz-tested that a restriction only ever narrows across
  fuzzed permission/scope combinations
  (`internal/core/pat_authz_metamorphic_fuzz_test.go`). *Residual*: none
  identified.
- **Machine identities — Spoofing.** Modelled separately from human
  users with their own lifecycle (`pending → active → suspended ⇄
  active`, `revoked` terminal, ADR-030); receive **no** admin-role
  bypass. *Residual*: none identified.
- **OIDC federation — Signing-key MITM / token forgery.** Asymmetric-only
  algorithm allowlist (`HS*`/`none` rejected, defeats key-confusion
  attacks), required `exp`, bounded `nbf` skew, issuer allowlist checked
  *before* key retrieval, audience intersection, `jwks_uri` must be
  `https` (loopback exempted for local development only) — ADR-031.
  *Residual*: none identified (`SECURITY-VERIFICATION.md` "ICT
  third-party risk / federation trust boundary").
- **SAML 2.0 SSO — Signature forgery / assertion replay.** Service
  Provider built on `crewjam/saml` + `goxmldsig` (never hand-rolled
  XML-DSig — hand-rolled signature verification is one of the
  highest-risk patterns in this entire threat surface); mandatory
  signature validation against a **pinned** IdP certificate,
  `AudienceRestriction`/`Recipient`/`NotBefore`/`NotOnOrAfter` checks,
  replay protection; IdP-initiated flow off by default (ADR-063).
  *Note on embargo*: per this repo's standing policy
  (`../testing.md`'s header note), a specific finding against
  `crewjam/saml` itself is embargoed pending upstream disclosure and is
  not detailed in any public document, including this one — only the
  mechanism (pinned-cert SP, no hand-rolled DSig) is described here.
- **TOTP MFA — Brute force / secret exposure.** RFC 6238, two-step login,
  single-use recovery codes, secret encrypted at rest (ADR-034).
- **WebAuthn/passkeys — Phishing / credential theft.** Origin-bound
  public-key assertions, no exportable shared secret, FIDO clone
  detection (ADR-036) — phishing-resistant by construction, unlike TOTP.
- **MFA mandate scoping — Elevation of privilege via policy gap.**
  `security.require_mfa` (deployment-wide) or a per-project override — a
  sensitive project can require MFA even when the global policy is off
  (ADR-037).
- **Emergency admin recovery — Elevation of privilege via host access.**
  `keyorix-server admin recover-admin` requires both host access and a
  separately-held, SHA-256-verified 256-bit recovery key; every use is
  audited and triggers an admin notification (ADR-108 decision B.2,
  `internal/recoverykey`). This is the one authentication mechanism
  where "host access + the recovery key = can authenticate as admin" is
  the accepted design ceiling, not a gap — see
  `../threat-model.md` §5.1 for the full insider-threat analysis of why
  two independent factors is the strongest practical bar for a local
  break-glass tool.
- **Impersonation — Repudiation.** Issues a separate short-lived session
  (the admin's own session is untouched); every action under it is
  tagged `impersonated_by`/`acting_as`, plus discrete
  `impersonation.start`/`.end` audit events.

## 4. Residual risks specific to this component

Carried forward from `../threat-model.md` §6, not re-derived: the
authentication cache window (~30s, above) is the one residual risk that
belongs specifically to this component rather than the system generally.
