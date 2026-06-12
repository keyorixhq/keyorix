# ADR-034: Multi-factor authentication (TOTP)

**Status:** Accepted
**Date:** 2026-06-12

## Context

Interactive human login used a password only. MFA was the one outstanding gap in
the authentication controls (the in-product 2FA panel was a placeholder), and
strong/multi-factor authentication is expected by NIS2 Art. 21(2)(j) and ENS
`op.acc.5/6` — directly relevant to the certification posture. We needed
per-user, opt-in second-factor authentication without disrupting the existing
session/RBAC machinery.

## Decision

Add **TOTP** (RFC 6238, `github.com/pquerna/otp`) as an opt-in second factor.

- **Enrolment is self-service.** `POST /auth/mfa/enroll` generates a secret and
  returns the `otpauth://` URI + base32 secret; `POST /auth/mfa/activate` confirms
  it with a code, enables MFA, and returns 10 single-use **recovery codes** (shown
  once). `POST /auth/mfa/disable` requires a current code or the password.
- **Two-step login via a short-lived pre-auth challenge.** When an MFA-enabled
  user passes the password step, `/auth/login` returns **no session** —
  `{mfa_required: true, mfa_challenge}`. `POST /auth/mfa/verify` consumes the
  single-use, 5-minute, hashed challenge, verifies the TOTP (or a recovery) code,
  and only then mints the session. Chosen over a "pending MFA" session flag so a
  `models.Session` always means *fully authenticated* — no half-authenticated
  session can ever reach secrets, and the auth middleware is untouched.
- **TOTP secret encrypted at rest.** The shared secret cannot be hashed (it is
  needed to compute the expected code), so it is stored **reversibly encrypted**
  via the server's initialised `encryption.Service` (KEK from
  `KEYORIX_MASTER_PASSWORD`), wired onto the core at startup
  (`SetAuthEncryptor`); passthrough when encryption is disabled, consistent with
  the rest of the product. Recovery and challenge tokens are SHA-256 hashed,
  single-use.
- **Auditable.** `mfa.enrolled/activated/disabled/login_verified/recovery_used/
  failed` flow through the existing audit pipeline.
- **±1 time-step skew** for clock drift; the `/auth/mfa/verify` endpoint is rate
  limited.

## Consequences

- Human logins can require a second factor; the access-control story now satisfies
  the MFA expectation for the certification track (controls docs updated to
  Shipped).
- One TOTP code attempt per challenge: a wrong code burns the challenge and the
  user re-authenticates. This is the simplest secure behaviour for v1; allowing a
  few attempts per challenge (verify-without-consume + rate limit) is a tracked
  UX follow-up.
- TOTP applies to interactive human login only — PAT/machine-token/OIDC paths are
  unchanged (those are non-interactive credentials with their own lifecycle).

## Deferred

WebAuthn / passkeys; per-project (vs deployment-wide) MFA policy;
trusted-device "remember this device"; multi-attempt-per-challenge UX.
