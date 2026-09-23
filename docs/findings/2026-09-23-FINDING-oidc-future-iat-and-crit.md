# FINDING: OIDC/SSO JWT verifiers accepted a future-dated `iat` and an unrecognized `crit` header

**Date:** 2026-09-23
**Component:** `internal/core/oidc.go` (`OIDCVerifier.Verify`, machine-identity
federation, ADR-031), `internal/core/sso.go` (`KeyorixCore.verifyIDToken`,
interactive SSO login).
**Status:** **Fixed**, same PR. Proving tests:
`TestOIDCVerifier_RejectsFutureIssuedAt`, `TestSSOVerifyIDToken_RejectsFutureIssuedAt`,
`TestOIDCVerifier_RejectsCritHeader`, `TestSSOVerifyIDToken_RejectsCritHeader`
(`internal/core/jwt_future_iat_crit_closure_test.go`), plus permanent seed
coverage in `FuzzOIDCIDTokenSingleConstraintViolation` /
`FuzzSSOIDTokenSingleConstraintViolation`
(`internal/core/jwt_single_constraint_fuzz_test.go`) and
`TestOIDCSSODifferential_SingleConstraintViolation`
(`internal/core/jwt_cross_verifier_differential_test.go`).
**Severity: Low** (future-iat bypass), **informational** (crit — RFC 7515
compliance gap, not independently exploitable by itself).

## Summary

A single-constraint-violation fuzz harness (`jwt_single_constraint_fuzz_test.go`,
built as part of a broader JWT/OIDC verification-constraint audit) builds a
fully valid token signed with the harness's own trusted key, violates exactly
one verification constraint per the fuzz input, and asserts 0 violations ⇒
accept, 1 violation ⇒ reject. Two rows failed the "1 violation ⇒ reject"
assertion, both an absence of a check rather than a broken one:

### 1. `iat` set arbitrarily far in the future (Low severity)

`OIDCVerifier.Verify` accepted a token whose `iat` claim was set into the
future, no matter how far. `oidc.go`'s existing max-age check
(`internal/core/oidc.go:201`, pre-fix) is:

```go
if age := v.effectiveNow().Sub(claims.IssuedAt.Time); age > trust.maxAge+v.leeway {
    return "", "", fmt.Errorf("oidc token exceeds max age (issued %s ago)", age.Round(time.Second))
}
```

A future-dated `iat` makes `age` **negative**, which can never exceed a
positive `maxAge+leeway` bound — so this check, whose entire purpose is to
bound how *old* a token may be, was silently unable to reject a token that
claims to be issued from the future. Every other constraint (trusted `iss`,
allow-listed `aud`, valid `kid`+signature, unexpired `exp`, non-empty `sub`)
can be satisfied simultaneously with a future `iat`, so this was independently
reachable — not masked by any other check.

Reproduced deterministically: `FuzzOIDCIDTokenSingleConstraintViolation`'s
committed seed for `jwtViolationIatFutureBeyondLeeway` (`iat = now + leeway +
1h`, everything else valid) failed before the fix.

`verifyIDToken` (the interactive SSO path, `sso.go`) has no max-age check at
all and was therefore not "bypassed" in the same sense — but the same
underlying gap (nothing bounds a future `iat`) was latent there too, and the
fix applies to it identically (see Fix below).

### 2. Unrecognized `crit` JOSE header (informational — RFC 7515 compliance)

RFC 7515 §4.1.11 requires a recipient to **reject** a JWS whose `crit` header
names a critical extension it doesn't understand. `golang-jwt/jwt/v5` has no
`crit`-header handling at all (confirmed by reading the library source — no
reference to `"crit"` anywhere in it), and neither `oidc.go` nor `sso.go`
checked for it independently, so a token carrying `"crit": ["anything"]` was
accepted on both paths regardless of what the header named. Since neither
verifier implements ANY JOSE extension, there was never a legitimate reason
for a `crit` header to be present — this is a pure fail-open gap relative to
the spec, not a bypass of a specific feature.

## Fix

Both fixes are additive parser-level checks; no existing check was loosened
or removed.

**Future `iat`:** added `jwt.WithIssuedAt()` (golang-jwt v5) to the parser
options in both `OIDCVerifier.Verify` and `verifyIDToken`. Per the library's
`Validator.verifyIssuedAt`, this rejects iff `now < iat - leeway`, i.e. an
`iat` more than the verifier's own clock-skew leeway (60s on both paths) into
the future — it does **not** touch the far-past direction and does **not**
make `iat` required. `OIDCVerifier.Verify` keeps its existing manual
iat-required + max-age check unchanged (it still owns "how old is too old");
`WithIssuedAt()` closes the one direction that check structurally could not.
`verifyIDToken` deliberately keeps no max-age ceiling and keeps accepting a
far-past `iat` — see "SSO iat-far-past stays excluded" below.

**`crit` header:** both `Verify` and `verifyIDToken` now reject any token
whose JOSE header contains a `crit` key at all, regardless of what it names —
consistent with recognizing zero extensions:

```go
if _, hasCrit := token.Header["crit"]; hasCrit {
    return "", "", fmt.Errorf("oidc token has an unrecognized crit header")
}
```

### Red-proofs (both directions, both verifiers)

All four scratch edits were made, confirmed red, then reverted before
committing (working tree clean between each):

- Removed `jwt.WithIssuedAt()` from `OIDCVerifier.Verify` →
  `FuzzOIDCIDTokenSingleConstraintViolation`'s `iat_future_beyond_leeway` seed
  failed (`CONSTRAINT BYPASS`).
- Removed `jwt.WithIssuedAt()` from `verifyIDToken` →
  `FuzzSSOIDTokenSingleConstraintViolation`'s `iat_future_beyond_leeway` seed
  failed, AND `TestOIDCSSODifferential_SingleConstraintViolation/kind=iat_future_beyond_leeway`
  failed (verifyIDToken accepted what OIDCVerifier.Verify correctly rejected).
- Disabled the `crit` check in `OIDCVerifier.Verify` →
  `FuzzOIDCIDTokenSingleConstraintViolation`'s `crit_header` seed failed, AND
  the differential's `kind=crit_header` sub-test failed.
- Disabled the `crit` check in `verifyIDToken` →
  `FuzzSSOIDTokenSingleConstraintViolation`'s `crit_header` seed failed, AND
  the differential's `kind=crit_header` sub-test failed.

## SSO `iat`-far-past stays excluded (unchanged, re-confirmed)

`verifyIDToken` still has no max-age ceiling — an `iat` ten years in the past
is still accepted (`TestJWTNotEnforcedConstraintMatrix`,
`jwt_not_enforced_report_test.go`). This was investigated and accepted as
in-scope-but-excluded before the fuzz harness was built, on two grounds
independently re-confirmed by direct code read (not re-litigated here, see
the original investigation for the full trace):

1. **Nonce required and single-use.** `sso.go:948` rejects an empty or
   mismatched nonce. The nonce is carried in the `SSOLoginState` row and
   consumed via a race-safe conditional `DELETE` (`local_sso.go:35-56`,
   `RowsAffected != 1` treated as not-found) the moment the login state is
   looked up — a captured id_token's nonce cannot be replayed into a second
   login regardless of how old its `iat` claims to be.
2. **id_token is never taken from the front channel.**
   `server/http/handlers/sso.go`'s callback handler reads only `code`/`state`
   from the query string; the id_token is obtained exclusively via the
   server-side token-endpoint exchange (`sso.go:217-223`,
   `p.OAuth.Exchange(...)` → `tok.Extra("id_token")`). There is no route by
   which an attacker-supplied id_token, however old, ever reaches
   `verifyIDToken` directly.

A max-age ceiling defends against a *long-lived, replayable bearer token* —
the OIDC machine-federation path's actual threat model, since that JWT
travels as a bearer credential on every authenticated request
(`server/middleware/auth.go`). The SSO id_token is consumed exactly once,
synchronously, inside a flow already bound by the single-use nonce; a
far-past `iat` on it carries no equivalent replay risk.

## Open design question (not changed): `typ` header for the machine-federation path

`typ` remains report-only (`TestJWTNotEnforcedConstraintMatrix`) — neither
verifier checks it, and this fix doesn't add a check. Worth flagging as an
open question specifically for `OIDCVerifier.Verify`: OAuth 2.0's explicit
token-type header convention (`at+jwt` for RFC 9068 JWT access tokens, plain
`JWT` for OIDC id_tokens) exists precisely to prevent an access token minted
by one authorization server component from being replayed where an ID token
is expected, or vice versa — the same *class* of confused-deputy risk this
verifier's `azp` check already defends against for multi-audience tokens.
`OIDCVerifier.Verify` consumes Kubernetes-projected service-account tokens
and arbitrary operator-configured OIDC issuers (ADR-031) — if any configured
issuer ever also mints RFC 9068 access tokens under the same signing key/kid
namespace, an access token could in principle be replayed here as a machine
identity credential. Today this is speculative (no confirmed issuer in this
codebase's supported configurations does that), so no behavior change was
made — but if a future issuer integration adds RFC 9068 access-token
issuance, requiring `typ` to be absent-or-"JWT" here (rejecting `"at+jwt"`
explicitly) would close that class before it's reachable, rather than after.

## Severity

**Future-iat: Low.** Requires the trusted issuer's own valid signature over a
token with an internally-inconsistent claim (`iat` in the future) — this is
not a signature forgery or key-confusion bug, and every other constraint
(trusted issuer, allow-listed audience, valid key/signature, unexpired `exp`,
non-empty subject) still had to hold. The concrete harm is narrow: it defeats
one specific defense-in-depth mechanism (the max-age freshness bound meant to
limit how long a federated token stays usable) without granting any access a
validly-signed, otherwise-conformant token wouldn't already grant via its
`exp`. A misconfigured or compromised trusted issuer minting future-dated
tokens could use this to make a token's *effective* validity window longer
than the max-age policy intends (up to `exp`), but could already mint a
long-`exp` token directly — this gap didn't provide a NEW forgery capability,
only removed one layer of an intentionally redundant freshness check.

**crit: informational.** No confirmed exploitation path — neither verifier
implements any JOSE extension a `crit` header could exploit by being ignored.
Fixed for RFC 7515 compliance and defense-in-depth (closing the header
unconditionally, rather than waiting until a specific extension makes it
exploitable).
