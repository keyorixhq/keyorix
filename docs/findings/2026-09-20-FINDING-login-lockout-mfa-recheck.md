# F1/F2: login lockout re-check and per-IP rate-limiter reserve-first race

Date: 2026-09-20
Status: F1 investigated, found already closed in current `main` (evidence
below, no code change). F2 confirmed real, FIXED in this PR.

## F1: does `Login`'s MFA branch skip the lockout re-check the non-MFA branch does?

**Investigated and found NOT reproducible against current `main`
(416b678e).** The two-step MFA/WebAuthn login flow already re-checks the
account lockout state, and clears it, immediately before minting a session —
in every completion path:

- `Login`'s own MFA branch (`internal/core/auth.go`) never mints a session
  at all — it returns `ErrMFARequired` and a short-lived challenge. The
  non-MFA branch's lockout re-check
  (`checkLockAndClearLoginFailures`, `auth.go:210`) has nothing to skip on
  this branch because there is no session-minting to gate here.
- `VerifyMFACredentials` (`internal/core/mfa.go:306`, the local completion
  path `VerifyMFALogin` calls) re-checks and clears the lock
  (`checkLockAndClearLoginFailures`, `mfa.go:357`) immediately after the
  TOTP/recovery code verifies and immediately before returning to the caller,
  which then mints the session.
- `FinishWebAuthnLogin` (`internal/core/webauthn.go:416`) does the identical
  re-check (`webauthn.go:463`) immediately before its own `mintSession` call.
- The `RemoteStorage` completion path (`VerifyMFALoginCredentials`,
  `internal/storage/store/remote_mfa.go:429`) proxies the ENTIRE second-factor
  check — including the lockout gate — to the upstream server, which runs
  the same `VerifyMFACredentials` locally.

Every completion path's own doc comment already states the TOCTOU reasoning
this finding describes ("a concurrent burst of failed second-factor attempts
against this account may have tripped the lock since the pre-verification
snapshot check above... re-check under the same serialization
`recordFailedLogin` uses before minting a session"), suggesting this was
already closed by an earlier hardening pass. No regression test was added
for F1 since there is no defect to pin; existing coverage
(`internal/core/mfa_test.go`, `internal/core/webauthn_test.go`) already
exercises these re-checks.

## F2: per-IP login limiter checks-then-records instead of reserving first

**Confirmed real.** Every unauthenticated auth endpoint that shares the
per-IP login-attempt budget (`core.LoginMaxAttempts`, 10 per 15 minutes) —
`Login`, `RefreshToken`, `VerifyMFA`, `BeginWebAuthnLogin`,
`FinishWebAuthnLogin`, `FinishWebAuthnPasswordlessLogin` — checked the
budget (`checkLoginRateLimit` → `IsLoginRateLimited`, a `COUNT(*)` read),
then ran the real (deliberately slow — bcrypt, TOTP, or a WebAuthn assertion
verification) credential check, and only recorded the attempt
(`recordLoginAttempt` → `RecordFailedLogin`, an `INSERT`) AFTERWARD, and only
on failure.

Because the check and the record were separated by the entire slow step, a
burst of concurrent requests from one IP all observed the SAME under-budget
count at their check (none of the others had recorded yet), all proceeded
through the slow verification, and only then recorded — letting a
concurrent burst blow through the 10-attempt budget before the counter ever
caught up. This is the exact check-then-act race the budget exists to
prevent, and it defeats the login rate limiter as a brute-force throttle
under any real concurrent attack (a single attacker opening many parallel
connections, not distributed across IPs).

### Fix

Renamed `recordLoginAttempt` → `reserveLoginAttempt` (`server/http/handlers/auth.go`)
and moved its call, at every one of the six affected call sites, to run
immediately after the request is minimally well-formed (decoded/parsed) and
BEFORE the slow credential check — not after it fails. The reservation is
now outcome-agnostic (like the pre-existing `RecordPasswordResetAttempt`/
`RecordSSOBeginAttempt` siblings in the same budget): a successful login now
also consumes one slot, trading a negligible cost for real users (10/15min
has ample headroom, and a two-step MFA/WebAuthn login already spent slots on
both steps before this change) for closing the race. A structurally
malformed request (bad JSON, no bearer token, no WebAuthn credential) still
does NOT consume a slot, matching the pre-fix behavior for that class of
request and avoiding penalizing non-guess traffic.

`ConsumeSetup` and `BeginWebAuthnPasswordlessLogin` share the same
`checkLoginRateLimit` gate but never called `recordLoginAttempt` at all,
even pre-fix — a narrower, separate gap (their own attempts never
contributed to the shared budget) left out of this PR's scope; noted here
for visibility, not fixed.

### Regression coverage

`server/http/handlers/login_rate_limit_reserve_test.go`:
`TestLogin_ConcurrentBurst_RateLimitBoundsCredentialChecks` fires 5
independent synchronized 30-request concurrent bursts (each on its own
fresh IP) of wrong-password `Login` calls and asserts the aggregate
too-many-requests count clears a threshold empirically far above what the
pre-fix ordering reaches and far below what the fixed ordering reaches
(single-round counts are individually noisy — see the test's own header
comment — the 5-round aggregate is stable). Red/green-verified by hand:
temporarily reverting `reserveLoginAttempt`'s call site back to
post-credential-check-on-failure-only made this test fail in 8/8 manual
runs (aggregate too-many-requests capped at 18-37 across runs, all below
the 40 threshold); restoring the fix passed 13/13 manual runs (aggregate
45-83, all above 40).
