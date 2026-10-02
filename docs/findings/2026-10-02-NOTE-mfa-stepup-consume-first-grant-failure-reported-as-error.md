# NOTE: `REST POST /api/v1/auth/mfa/stepup`'s consume-first design reports a `CreateMFAStepUpGrant` failure as an error with the TOTP step still consumed — intentional and already test-proven, not a bug

**Date:** 2026-10-02
**Component:** `internal/core/mfa_stepup.go` (`VerifyMFAStepUp`).
**Status:** NOT a bug — a harness-oracle gap (same shape as the other
NOTE in this directory, `2026-10-02-NOTE-bulk-access-request-ops-audit-content-diverges-on-item-failure.md`).

## Summary

`VerifyMFAStepUp`'s own doc comment (line 61-65) states this explicitly:
"atomicity: consume-first by design (Session O, O4) — the TOTP step ... is
consumed BEFORE VerifyMFAStepUp creates the MFAStepUpGrant. A later
grant-creation failure must not un-consume it" — proven by
`TestVerifyMFAStepUp_GrantFailureAfterConsume_FailsClosed`
(`consume_first_fails_closed_test.go`), which injects exactly this
`CreateMFAStepUpGrant` failure and confirms no grant is issued and the step
stays consumed.

`FuzzStorageFaultOperations` found the identical shape independently while
extending this op's coverage (SESSION-FI2):

```
input=c578 -> op="REST POST /api/v1/auth/mfa/stepup" fault=(method=CreateMFAStepUpGrant, NthCall=1, kind=error)
ORACLE (a) VIOLATION — reported an ERROR but logical state changed anyway (partial commit). Differing tables: [MFASecret]
```

Seed committed at
`server/faultops/testdata/fuzz/FuzzStorageFaultOperations/57a32a29aeb22f38`.

This is not new information about the application — it is the SAME
intentional tradeoff the function's own comment and dedicated unit test
already document and prove correct (a correct TOTP code is sacrificed
rather than risk re-granting on retry, failing closed). The gap is that
`checkOracles`' default (error) branch has no "acceptable-by-design"
exemption mechanism, unlike the success branch's `bestEffortTables`/
`opScopedBestEffortTables` — the same gap the bulk-access-request NOTE
above already flagged and deferred ("extending it needs its own validation,
not bundled into this op's own fix"). Tolerated here via the same
`knownOpenTolerances` mechanism as a pragmatic stand-in, narrowly scoped
(table=MFASecret only), rather than building a new error-branch exemption
mechanism ad hoc.
