# ADR-031: OIDC / Kubernetes-JWT federation for machine identities

**Status:** Accepted
**Date:** 2026-06-10
**Context:** ADR-030 let machine identities authenticate with Keyorix-issued
opaque bearer tokens and be authorized via `machine_identity_roles` +
`AuthorizePrincipal`. The deferred half was **federation**: letting a workload
present a token its platform already issues — a Kubernetes projected
service-account token, or any OIDC ID token — instead of a long-lived Keyorix
secret it has to store.

## Context

A Kubernetes pod gets a short-lived, auto-rotated projected service-account JWT
mounted at `/var/run/secrets/.../token`. It is signed by the cluster, carries an
`iss` (the cluster's issuer URL), a `sub` (`system:serviceaccount:<ns>:<name>`),
an `aud`, and an `exp`, and is verifiable against the cluster's public JWKS. If
Keyorix can verify that token and map it to a machine identity, the workload
authenticates with **no stored secret at all** — the strongest machine-auth
posture.

This builds directly on ADR-030: a federated token resolves to the *same*
machine principal, authorized by the *same* `machine_identity_roles`, audited
with the *same* `actor_type = machine_identity`. Only the front door — how a
request resolves to a machine — is new.

## Decision

### Trusted issuers (config)

`auth.oidc.issuers` is an operator-curated allowlist. Each entry has a `name`,
an `issuer` (must match the JWT `iss` exactly), a `jwks_uri` (where the signing
keys live), and `audiences` (the JWT `aud` must contain one). A token is only
considered if its `iss` matches a configured issuer; an empty/disabled config
means OIDC auth is off. **Trust is explicit** — Keyorix never auto-discovers or
trusts an arbitrary issuer.

### Bindings — `machine_identity_oidc_bindings`

A binding maps `(issuer, subject)` → a machine identity (unique on
`(issuer, subject)`, so one cluster SA maps to exactly one machine). An operator
creates it (`POST …/machine-identities/{id}/oidc-bindings` with `{issuer,
subject}`), gated by `roles.assign` at the machine's project, with the same
cross-project guard as ADR-030's token endpoints.

### Verification

`OIDCAuthenticator.ValidateToken(raw)`:
1. Parse the JWT, read `iss`; reject unless `iss` is a configured issuer.
2. Verify the **signature** (RS256/ES256) against the issuer's JWKS, resolving
   the key by `kid` (golang-jwt does the crypto). JWKS are fetched from
   `jwks_uri` and cached, refreshed on an unknown `kid` (handles key rotation).
3. Validate `aud` (intersects the issuer's configured audiences), `exp`/`nbf`
   with a small clock-skew leeway, via golang-jwt's validator.
4. Look up the `(iss, sub)` binding → machine identity; require it `active`.
5. Resolve the machine's roles (`GetMachineRoles`) and return the machine
   principal.

The JWKS source is behind a small `jwksResolver` interface so the verification
logic is unit-testable with a generated key and no network.

### Middleware

`validateToken` already routes `kx_pat_` / `kx_machine_` prefixes. A bearer that
is a **three-segment dotted JWT** (and not one of those prefixes) routes to the
OIDC authenticator when it is configured. Success builds the *same* machine
`UserContext` (UserID 0, `MachineIdentityID` set, `ActorType =
machine_identity`) as an opaque machine token — so RBAC, scope confinement, and
audit actoring are identical and already tested.

## Consequences

- A Kubernetes/CI/OIDC workload authenticates with a platform-issued,
  short-lived, auto-rotated token — **no Keyorix secret to store or leak**.
- The blast radius is tiny on the authorization side: federation only adds a new
  way to *resolve* a request to an existing machine principal; everything
  downstream (RBAC, no-admin-bypass, audit, scope confinement) is ADR-030,
  unchanged.
- Trust is explicit and operator-curated; an unconfigured issuer is rejected,
  signatures are verified against the issuer's own JWKS, and `aud`/`exp` are
  enforced — the standard OIDC verification guarantees.
- A revoked/suspended machine identity disables its federated access too
  (validation re-checks machine state every request, same as opaque tokens).
