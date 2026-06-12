# ADR-036: WebAuthn / passkeys (phishing-resistant second factor)

**Status:** Accepted
**Date:** 2026-06-12

## Context

TOTP MFA (ADR-034) closed the basic strong-authentication gap, but a shared-secret
OTP is still phishable: a user can be tricked into typing a code into a lookalike
site, and the secret exists in two places (the server and the authenticator app).
WebAuthn / FIDO2 (passkeys, security keys) is **origin-bound public-key
authentication** — the private key never leaves the authenticator and assertions
are cryptographically scoped to the relying party's origin, so a phishing site
cannot relay them. NIS2 Art. 21(2)(j) and ENS `op.acc.6` both favour
phishing-resistant MFA; this adds it as an opt-in second factor alongside TOTP.

## Decision

Add **WebAuthn** (`github.com/go-webauthn/webauthn`) as a second factor that
parallels the existing TOTP two-step login.

- **Self-service registration.** `POST /auth/webauthn/register/begin` returns the
  `CredentialCreation` options + an opaque `webauthn_session` token;
  `POST /auth/webauthn/register/finish` (with the attestation + a user label)
  verifies it, stores the credential, and sets `User.WebAuthnEnabled`. Existing
  credentials are passed as exclusions so the same authenticator can't be
  double-registered. `GET`/`DELETE /auth/webauthn/credentials[/{id}]` list and
  remove passkeys; removing the last one disables WebAuthn for the account.
- **Two-step login, reusing the MFA challenge.** When a user with *any* second
  factor (TOTP or a passkey) passes the password step, `/auth/login` returns no
  session — `{mfa_required, mfa_challenge, totp_available, webauthn_available}`.
  For a passkey the client calls `POST /auth/webauthn/login/begin` (with the
  challenge) to get assertion options, then `POST /auth/webauthn/login/finish`
  (challenge + assertion); finish consumes the single-use challenge, verifies the
  assertion, advances the signature counter, and mints the session. The TOTP path
  (`/auth/mfa/verify`) is unchanged — the two are interchangeable second factors.
- **Ceremony state is server-side, single-use, hashed.** The go-webauthn
  `SessionData` (challenge, allowed credentials, UV requirement) is persisted in
  `web_authn_sessions` under the SHA-256 hash of an opaque token, 5-minute TTL,
  consumed atomically — the same hash-at-rest pattern as `mfa_challenges`. No
  half-authenticated `Session` is ever created; a `models.Session` still means
  fully authenticated.
- **Credentials** are stored as the library's canonical JSON `Credential` blob
  (public key, attestation, signature counter, transports) plus an indexed raw
  `CredentialID`. The blob is rewritten on each login to track the signature
  counter; a non-advancing counter raises a `webauthn.clone_warning` audit event.
- **Relying party** (`RPID`, `RPOrigins`, display name) comes from a new
  `webauthn` config block; absent/disabled, the passkey endpoints return 501 and
  login behaves exactly as before.
- **`require_mfa` integration.** The deployment-wide MFA-enrolment enforcement
  (ADR-034 follow-up) treats a passkey as satisfying the requirement, and its
  confinement allowlist includes the WebAuthn registration endpoints, so a user
  can enrol a passkey to satisfy the policy. Non-interactive credentials (PAT /
  machine / OIDC) remain exempt.

## Security properties

- **Phishing-resistant:** assertions are origin-bound by the authenticator; the
  RP validates the origin against the configured `RPOrigins`.
- **No exportable shared secret:** only the public key is stored; a database read
  cannot impersonate the user (unlike a TOTP secret, which must be reversibly
  stored).
- **Single-use, short-lived ceremony tokens** hashed at rest; the login assertion
  is gated by the same single-use challenge as TOTP — no second factor can be
  completed without first passing the password step.
- **Clone detection** via the FIDO signature counter, audited.
- **Self-service only & user-scoped:** every endpoint acts on the authenticated
  caller; credential deletion is scoped by user id, so one user cannot remove
  another's passkey.

## Verification

Core tests against real SQLite + a configured relying party: the login gate
returns `ErrMFARequired` for a passkey-enabled account; a disabled server rejects
with `ErrWebAuthnDisabled`; the registration ceremony session is single-use and
hashed; login-begin resolves the user from the (un-consumed) challenge, requires a
registered passkey, and binds the user's credential into `allowCredentials`;
finish rejects a webauthn session belonging to another user/challenge before any
crypto; deleting the last passkey clears the flag and deletion is user-scoped.
`make build` + full suite + `go vet` green. (The FIDO attestation/assertion crypto
itself is covered by the go-webauthn library's own test suite.)

## Deferred

"Remember this device" trusted-device skip; per-credential UV policy and
attestation-format allowlists; WebAuthn for the CLI. WebAuthn (second factor or
passwordless) is for interactive human login, not PAT/machine/OIDC paths.

## Addendum (2026-06-12): passwordless (usernameless) login

The originally-deferred discoverable-credential flow shipped: a registered passkey
alone can mint a session, no password.

- **Registration** now requests a **discoverable (resident) credential**
  (`ResidentKeyRequirement: preferred` — backward-compatible; authenticators that
  can't store a resident key still register for the second-factor flow), so the
  passkey can later be found usernamelessly.
- **`POST /auth/webauthn/passwordless/begin`** (public, no body) →
  `BeginDiscoverableLogin` with **user verification REQUIRED**, so the single
  passkey gesture proves *possession + user* (MFA-grade) — a complete login, not
  just a possession check. Returns assertion options + an opaque ceremony session.
- **`POST /auth/webauthn/passwordless/finish`** `{webauthn_session, credential}` →
  consumes the single-use session, and a `DiscoverableUserHandler` resolves the
  user from the assertion's **user handle** (our 8-byte `WebAuthnID`).
  `ValidatePasskeyLogin` then verifies the assertion **against that user's own
  stored credentials** — so a forged user handle can't be paired with someone
  else's credential. The account-state gate (`AccountLoginBlocked`) is enforced
  here, since there is no password step to gate a suspended account. Audited
  `webauthn.passwordless_login`.

Because the resulting session belongs to a `WebAuthnEnabled` user, it satisfies
the `require_mfa` mandate inherently. Still deferred: trusted-device skip,
per-credential UV/attestation policy, CLI WebAuthn.
