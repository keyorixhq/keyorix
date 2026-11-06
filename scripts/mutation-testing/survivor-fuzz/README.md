# survivor-fuzz: fuzz the surviving mutants

A `LIVED` gremlins mutant means no test failed when one operator in the code was
changed. Two explanations: the mutant is *equivalent* (no input can tell the two
programs apart), or the tests have a gap. This tool tells them apart in the cheap
direction: it runs the original function and the mutated function side by side on
fuzzed input and reports whether any input makes them disagree. A disagreeing
input is, by construction, a test that kills the mutant.

```
survivor-fuzz.sh --repo <keyorix checkout> --fuzztime 5m "CONDITIONALS_NEGATION account_sessions.go:48:13"
```

Verdict words: `killed-by-input`, `likely-equivalent` (no difference found in the
time given, not a proof), `harness-missing`, `no-node`. See the header of
`survivor-fuzz.sh` for the mechanism and `mutate/` for the mutator (gremlins has
no "apply one mutant" command, so the operator rewrites are re-created there).

Why it lives next to `run-mutation.sh`: its input is the gremlins `LIVED` list that
script produces, and it is run by the same people on the same kind of box.

Harnesses are hand-written, one per function (`harnesses/<Func>_test.go.txt`,
copied into the package as an in-package `_test.go` so unexported helpers are
reachable). Writing the harness is the real work: the fuzzer has no comparison
tracing, so an input encoding must make boundary values reachable (for example
"age = days*24h + a small signed delta" instead of a raw int64).

Survivor positions are only valid against the commit the mutation run used.

## Pre-registered pilot (written before any run)

Date: 2026-11-06. Package `internal/core`, survivor list from the CT 100 run of
2026-11-04 (`last-core.log`, 57 `LIVED`), positions valid at keyorix commit
`9a0c68079`.

Survivors tried (chosen by security relevance and cheap harness, fixed now):

1. `CONDITIONALS_BOUNDARY access_review.go:90:42` highestSecretsAction
2. `CONDITIONALS_BOUNDARY account.go:624:27` PasswordExpired (expiry boundary)
3. `CONDITIONALS_NEGATION account_sessions.go:48:13` RevokeUserSessions (admin-rank guard)
4. `CONDITIONALS_NEGATION alert_escalation.go:66:29` minEscalateDelay
5. `CONDITIONALS_BOUNDARY alert_escalation.go:66:29` minEscalateDelay (expected equivalent: a control)
6. `CONDITIONALS_BOUNDARY alert_escalation.go:293:21` postJSONToURL (status >= 400)
7. `CONDITIONALS_BOUNDARY access_review_campaign.go:493:31` CloseAccessReviewCampaign
8. `CONDITIONALS_NEGATION access_review_revoke.go:99:14` enforceAccessReviewReviewerControls
9. `CONDITIONALS_NEGATION access_review_campaign.go:452:18` checkForceCloseIndependence
10. `CONDITIONALS_BOUNDARY alerts_write_role_reconcile.go:109:13` ReconcileAlertsWriteRole

Each gets at most 5 minutes with `-parallel 2` on a laptop. A survivor with no
harness is reported as `harness-missing` and still counts as tried.

**Success rule:** at least one of the ten ends `killed-by-input`, and its input,
written as a plain unit test on current `main`, fails against the mutant and
passes against the original, in a security-relevant function (authorization,
sessions, expiry, audit). Otherwise the pilot **did not pay off** and is recorded
that way. Harness-missing and likely-equivalent results are reported, not hidden.

## Results

Run 2026-11-06, MacBook Air under heavy shared load, 5 minutes per survivor
(-parallel 2), against commit `9a0c68079`. Raw logs and inputs are not committed.

| # | Survivor | Function | Verdict |
|---|----------|----------|---------|
| 1 | BOUNDARY access_review.go:90:42 | highestSecretsAction | killed-by-input (unknown action ranks 0, `>=` would report it) |
| 2 | BOUNDARY account.go:624:27 | PasswordExpired | killed-by-input (maxAgeDays=81, delta 0: exactly at the limit) |
| 3 | NEGATION account_sessions.go:48:13 | RevokeUserSessions | killed-by-input (plain user revokes the admin's sessions) |
| 4 | NEGATION alert_escalation.go:66:29 | minEscalateDelay | killed-by-input (seed {5,3,9}: min 3 vs 9) |
| 5 | BOUNDARY alert_escalation.go:66:29 | minEscalateDelay | likely-equivalent (control: `<=` returns the same value) |
| 6 | BOUNDARY alert_escalation.go:293:21 | postJSONToURL | harness-missing (send-time URL guard refuses loopback test servers) |
| 7 | BOUNDARY access_review_campaign.go:493:31 | CloseAccessReviewCampaign | harness-missing (needs campaign state in storage) |
| 8 | NEGATION access_review_revoke.go:99:14 | enforceAccessReviewReviewerControls | harness-missing (needs a machine identity created by the actor) |
| 9 | NEGATION access_review_campaign.go:452:18 | checkForceCloseIndependence | killed-by-input (actor's own pending item) |
| 10 | BOUNDARY alerts_write_role_reconcile.go:109:13 | ReconcileAlertsWriteRole | harness-missing |

Counts: killed-by-input 5, likely-equivalent 1, harness-missing 4.

**Against the pre-registered rule: success.** At least one input became a plain
unit test on current `main` (`internal/core/survivor_fuzz_regression_test.go`,
five tests) that passes on the original and fails on the mutant. This was
checked by applying each mutation to a clean checkout of `main` (ea076b340) and
running the new test: 5 of 5 killed, baseline green. The most security-relevant
gaps were #3 (the admin-rank ceiling on session revocation had no test with a
lower-ranked actor) and #9 (ARC-002: nothing tested that a pending item of the
force-closing actor blocks the force-close).

Limits: 4 of 10 harnesses were not written, so "killed-by-input 5/10" is 5 of the
6 survivors that had a harness; the equivalent verdict is one control, not a
statistic; the first run's compile time on a loaded laptop dominated (about 3
minutes), so a box like CT 100 is the right place for larger batches; harnesses
are hand-written, automation was not attempted.
