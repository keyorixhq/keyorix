# FINDING: a panic in `mintSession`'s best-effort `EnforceSessionLimit` call reports an otherwise-successful MFA login as failed, even though the session row already committed

**Date:** 2026-10-02
**Component:** `internal/core/auth.go` (`mintSession`, line 184-191).
**Status:** **Open, not fixed in this session** — found while extending the
fuzz target's coverage of `REST POST /auth/mfa/verify` (SESSION-FI2), out of
that session's OWNS (`server/faultops/**`); filed per the campaign's
standing practice of not fixing out-of-scope findings in the session that
found them.

## Summary

```go
created, err := c.storage.CreateSession(ctx, session)
if err != nil {
	return nil, fmt.Errorf("failed to create session: %w", err)
}
// Bound concurrent sessions per user so unbounded logins can't grow the table or
// enlarge the credential-theft blast radius. Best-effort — never fail a login on it.
_ = c.storage.EnforceSessionLimit(ctx, userID, maxSessionsPerUser)
return created, nil
```

`_ = c.storage.EnforceSessionLimit(...)` discards a RETURNED error, matching
its own "best-effort" comment — but it does nothing for a PANIC, which
propagates straight past this line. By the time `EnforceSessionLimit` runs,
`CreateSession` has already committed and (for the MFA-verify op
specifically) `MarkTOTPStepUsed` already consumed the caller's TOTP step —
both real, successful effects of a login that supplied the CORRECT code.
The panic is caught further up the stack by the transport's own
panic-recovery wrapper and converted to a 500, so the caller is told the
login failed, while a live session row (and a consumed TOTP step) already
exist server-side.

## Reachability

Reachable on EVERY successful login (password or MFA) that mints a
session, whenever `EnforceSessionLimit` panics — not specific to MFA, though
found here via the MFA-verify op.

## Reproduction (fuzzer trace)

Found by `FuzzStorageFaultOperations`'s own exploration (not seeded) while
extending coverage on `REST POST /auth/mfa/verify`:

```
input=c62ccb3231 -> op="REST POST /auth/mfa/verify" fault=(method=EnforceSessionLimit, NthCall=1, kind=panic) principal=admin (bootstrapped)
ORACLE (a) VIOLATION — reported an ERROR but logical state changed anyway (partial commit). Differing tables: [LoginAttempt Session MFASecret]
```

Seed committed at
`server/faultops/testdata/fuzz/FuzzStorageFaultOperations/9c5248486d526fb4`.

1. Setup enrols TOTP and mints a live `MFAChallenge` (same shape as the
   op's existing Setup).
2. Fault armed: `(method=EnforceSessionLimit, NthCall=1, kind=panic)`.
3. Execute posts a genuinely valid TOTP code.
4. `MarkTOTPStepUsed` commits (the step is consumed), `CreateSession`
   commits, then `EnforceSessionLimit` panics.
5. The transport's recovery wrapper converts the panic to a 500. The caller
   sees "login failed" for a request that, server-side, fully succeeded.

## Impact

- **Availability/correctness, not an authz bypass:** a legitimate user is
  told their correct-code login failed while a session they can't retrieve
  (the token was never returned) sits in the table, and their TOTP step is
  now spent — a retry with the SAME code (now a replay) would also fail,
  forcing the user to wait for the next TOTP window.
- Same root-cause shape as this session's other "effect committed, reported
  as failure" findings (gRPC CreateRole/UpdateRole, CreateUser).

## Suggested fix (not applied here)

Wrap the `EnforceSessionLimit` call in its own `recover()` (mirroring
`notifySecretAccessRequested`'s fix for the identical shape, #2041) so a
panic in this best-effort cleanup can never mask an already-committed,
successful session mint.

## Fix status

**Not fixed.** Tolerated in
`server/faultops/fuzz_storage_fault_operations_test.go`'s
`knownOpenTolerances` (op=`REST POST /auth/mfa/verify`, method=
`EnforceSessionLimit`, kind=panic, tables=[LoginAttempt, Session,
MFASecret]) so the committed corpus entry above can be replayed as a
permanent regression pointer without failing CI on an open, out-of-scope
finding — remove that tolerance entry when this is fixed, per its own doc
comment.
