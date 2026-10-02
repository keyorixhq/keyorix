# FINDING: a transient `GetMFASecret` storage error during TOTP login verification is silently treated as "wrong code" — audited as a failed MFA attempt and counted toward the account lockout, indistinguishable from an actual bad code

**Date:** 2026-10-02
**Component:** `internal/core/mfa.go` (`VerifyMFACredentials`, line
265-311, via `loadTOTPSecret` line 355-361).
**Status:** **Open, not fixed in this session** — found while wiring the
new `REST POST /auth/mfa/verify` opCatalog entry (SESSION-FI, AT5); out of
that session's OWNS (`server/faultops/**`, `internal/storage/migrations/**`,
`scripts/fuzzing/targets.d/**`), filed per the campaign's standing
practice of not fixing out-of-scope findings in the session that found
them.

## Summary

```go
func (c *KeyorixCore) VerifyMFACredentials(ctx context.Context, challenge, code string) (*models.User, bool, error) {
	...
	verified, usedRecovery := false, false
	if secret, err := c.loadTOTPSecret(ctx, ch.UserID); err == nil {
		if step, ok := c.validateTOTPStep(secret, code); ok {
			if fresh, ferr := c.storage.MarkTOTPStepUsed(ctx, ch.UserID, step); ferr == nil && fresh {
				verified = true
			}
		}
	}
	if !verified {
		if consumed, err := c.storage.ConsumeMFARecoveryCode(ctx, ch.UserID, sha256Hex(normalizeRecoveryCode(code)), c.now()); err == nil && consumed {
			verified, usedRecovery = true, true
		}
	}
	if !verified {
		c.auditMFAFailed(ctx, ch.UserID, "login")
		c.recordFailedLogin(ctx, user) // count the failed second factor toward the lockout
		return nil, false, fmt.Errorf("invalid code")
	}
	...
}
```

`loadTOTPSecret`'s error (`c.storage.GetMFASecret` failing — a transient
read error, lock contention, connection hiccup) is checked with `err ==
nil` as the gate to even ATTEMPT TOTP validation. When it errors, the
whole TOTP branch is silently skipped — `verified` stays `false` exactly
as if the caller had typed the wrong 6-digit code. Execution falls through
to the recovery-code fallback (which also fails, since no recovery code
was supplied in the normal TOTP flow), and then to the `!verified` branch:
**the caller's MFA attempt is audited as a failed login AND counted toward
the account's lockout threshold** (`recordFailedLogin`) — for a request
that never actually got to check whether the code was right.

This is the same root-cause SHAPE as this session's other finding
(`2026-10-02-FINDING-sod-policy-create-getrole-error-misread-as-not-admin.md`):
a storage-read failure during a security decision collapses into the same
outcome as a confirmed negative result, rather than being surfaced as "the
check could not be completed." Here the consequence is more serious than
the SoD case: repeated transient storage hiccups during login (not actual
wrong-code attempts) silently accumulate against the SAME lockout counter
real brute-force attempts trip, risking a legitimate user's account
lockout for reasons entirely unrelated to their own behavior.

## Reachability

Directly reachable by any user completing the standard password + TOTP
login flow (`POST /auth/login` → `POST /auth/mfa/verify`), whenever the
one `GetMFASecret` read inside `VerifyMFACredentials` fails.

## Reproduction (fuzzer trace)

Found by `FuzzStorageFaultOperations`'s own exploration (not seeded),
continuing the same burst that found this session's other findings,
failing at 81s (after minimization):

```
input=c688c2 -> op="REST POST /auth/mfa/verify" fault=(method=GetMFASecret, NthCall=1, kind=error) principal=admin (bootstrapped)
ORACLE (a) VIOLATION — reported an ERROR but logical state changed anyway (partial commit). Differing tables: [AuditEvent LoginAttempt]
```

Minimized input saved at
`server/faultops/testdata/fuzz/FuzzStorageFaultOperations/31fd1db68a395324`,
replayable via `go test ./server/faultops/... -run
'FuzzStorageFaultOperations/31fd1db68a395324' -v`.

1. **Setup:** `enrolMFADirect` (this session's own new helper,
   `opcatalog_test.go`) enrols the bootstrapped admin in TOTP MFA via the
   real enroll endpoint, flips `Activated`/`MFAEnabled` directly via
   storage (bypassing `/activate`'s own TOTP consumption so the step
   Execute uses is still fresh), then mints a live `MFAChallenge` via
   `core.CreateMFAChallenge`.
2. **Fault armed:** `(method=GetMFASecret, NthCall=1, kind=error)`.
3. **Execute:** `POST /auth/mfa/verify` with the matching challenge and a
   freshly-generated, genuinely VALID TOTP code for that exact moment.
4. `loadTOTPSecret`'s `c.storage.GetMFASecret` call hits the injected
   fault. The TOTP branch is skipped entirely — the valid code is never
   actually checked against anything.
5. `auditMFAFailed` writes an `AuditEvent` row; `recordFailedLogin` writes/
   updates a `LoginAttempt` row — both recording this as a failed
   second-factor attempt.
6. The RPC returns `401 Invalid or expired code` to a caller who supplied
   the CORRECT code. The reference (fault-free) run, by contrast,
   successfully verifies and mints a session — so this faulted run's
   `AuditEvent`/`LoginAttempt` diff versus the PRE-EXECUTE baseline (not
   just versus the reference) is real new state: a failed-attempt record
   for an attempt that was never actually evaluated.

## Impact

- **Availability — the most concrete consequence in this family of
  findings so far:** `recordFailedLogin`'s accumulated count is what
  drives `loginLocked`'s lockout decision (confirmed by this file's own
  `VerifyMFACredentials`, line 287: `if c.loginLocked(user) { ... account
  temporarily locked ... }`, checked on every subsequent attempt). A
  transient storage blip during MFA — not a password guess, not an
  attacker, just infrastructure — counts exactly the same as a genuine
  wrong-code attempt toward locking a real user out of their own account.
  A handful of such hiccups in a row (plausible under real storage
  contention) can lock someone out with no wrongdoing on their part.
- **Audit trail integrity:** `mfa.failed` events accumulate for attempts
  that were never actually checked, same class of misleading audit record
  as this session's SoD finding.
- **Likelihood:** any transient failure on this one read during ANY TOTP
  login verification triggers it — no adversarial setup required, and
  unlike some findings in this campaign, this is on the EVERY-LOGIN hot
  path for every MFA-enabled account, not a rarely-hit administrative
  action.

## What this is NOT

- Not a privilege escalation or authz bypass — the failure mode is
  fail-**closed** (denies a legitimate, correct-code login), not fail-open.
- Not a replay/anti-replay bug — `MarkTOTPStepUsed`'s single-use
  enforcement is untouched by this; the issue is purely that a storage
  READ error short-circuits to "wrong code" instead of "could not check."

## Suggested fix (not applied here)

Distinguish `loadTOTPSecret`'s error from a confirmed "no valid code
presented" in `VerifyMFACredentials`: a `GetMFASecret` failure should
surface as a distinct, retryable error (not silently fall through to
`recordFailedLogin`'s lockout-counted path), mirroring
`roleSetContainsAdmin`'s own documented precedent one file over
(`internal/core/authz.go:383-390`: "Fails closed on a genuine resolution
error: any storage error is returned to the caller rather than silently
treated as... — a lookup error on a security-relevant path must not be
indistinguishable from a legitimate negative result, or a caller can
trigger the same lookup error to silently bypass whatever the error would
otherwise have blocked" — the same principle, applied here to AVOID a
false lockout contribution rather than to avoid a false allow).

## Fix status

**Not fixed.** Tolerated in `server/faultops/fuzz_storage_fault_operations_test.go`'s
`knownOpenTolerances` (op=`REST POST /auth/mfa/verify`, method=
`GetMFASecret`, kind=error) so the corpus entry above can be committed as
a permanent regression pointer without failing CI on an open, out-of-scope
finding — remove that tolerance entry when this is fixed, per its own doc
comment.
