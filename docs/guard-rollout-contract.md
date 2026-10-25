# Guard rollout contract

A repo-wide guard is a test that walks the repository (go/parser, go/ast,
`filepath.WalkDir`, a sweep over every route, model or ledger row) or a
registry that most PRs touch. One red guard fails every merge-queue entry
behind it, so a guard must not go red because of something the PR in front of
it did not do. Between 27 Sep and 24 Oct 2026 this class (A in the merge-queue
month analysis) failed the queue for days at a time. The two rules below cover
the instances caused by the calendar or by a new or widened guard; the table at
the end says which instances need another measure.

## Rule 1: no calendar at PR time

A PR or merge-queue check never decides pass/fail from the wall clock. An
exemption row with an expiry date is either present or absent; whether its
date has passed is evaluated only by the nightly job on main.

- Validate the date's format in the guard (`YYYY-MM-DD`).
- Hand the date to `guardrules.CheckExpiry` (`internal/guardrules`) from a test
  named `Test*NotExpired`. Without `KEYORIX_GUARD_EXPIRY_TODAY` it checks the
  format only. The nightly job sets it, warns 7 days ahead, and fails on an
  expired row.
- `scripts/guard-expiry-report.sh` is that job: it runs every `Test*NotExpired`
  test in every package that calls `CheckExpiry`, plus the TEMPORARY rows of
  `scripts/ci-test-legs.sh` (30-day budget), and writes the report the nightly
  workflow puts into one GitHub issue (opened, updated, closed when clear).
- Enforced by `TestGuardTestsDoNotReadTheCalendar`: a `_test.go` file that reads
  the clock (`time.Now`, `time.Since`, `time.Until`) and parses or formats a
  date-only value fails, wherever it is in the repository.
  `TestCheckExpiryCallersAreNamedNotExpired` keeps every `CheckExpiry` call
  inside a test the nightly job will run.

## Rule 2: report-only for the first day, proven against the open PRs

A new repo-wide guard, or a change that widens what an existing guard covers:

1. Reports through `g := guardrules.Rollout(t)` and uses `g` for every finding
   (`g.Errorf`, `require.X(g, ...)`). Helpers take `testing.TB`.
2. Ships with `docs/guard-rollout.d/<TestName>.tsv` (one row: test, package,
   introducing PR, reason). While the row exists the guard is report-only on
   pull_request and merge_group runs: a finding is logged as
   `GUARD REPORT-ONLY (... would fail)` and a fatal one skips the test. On pushes
   to main and on the nightly schedule CI sets `KEYORIX_GUARD_ROLLOUT=enforce`,
   so the guard is already blocking on main itself.
3. Shows in its PR body the output of
   `scripts/guard-meets-open-prs.sh -p ./<pkg> -r '<TestRegex>' [PR...]`: the
   guard over origin/main plus the merge results of the most recently updated
   open PRs (at least 5), with this branch applied on top. Every PR it would fail
   is named, and its author is told before the guard merges.
4. Becomes blocking when its row is deleted: after at least one nightly run on
   main with the guard enforced and green, the coordinator's promotion script
   opens one PR that deletes every row that qualifies.

`TestGuardRollout_RowsNameAReportingGuard` fails on a malformed row or a row
whose test does not call `Rollout`.

Not covered, by design: guards in the `cli/` and `operator/` modules (they
cannot import `internal/guardrules`; rule 1 is still checked there by the
calendar guard), and shell or workflow checks (the CI `exclusion-freshness` job
reads dates in shell; the workflow change moves it to the nightly schedule).

## The history behind each rule

| incident (queue failures) | what happened | rule that prevents it |
|---|---|---|
| TestChildParentLiveness_EveryChildInsertLocksItsParent, 5-9 Oct | The guard's own PR (#2728) sat in the queue for 5 days: each time a lock fix merged ahead of it, its exemption rows went stale ("delete them") and the run failed, failing the entries behind it too (#2824, #2832, #2882, #2825). | 2: report-only rows log instead of failing; the open-PR run names the lock-fix PRs that make rows stale before the guard enters the queue. |
| TestCompletenessGuard_EntrypointsAndStoresMatchCode, 4-5 Oct | docs/state-map/*.tsv is a committed inventory (with a REVIEW-row ratchet) that every PR adding a route, table or file write must update; queue entries whose merge result no longer matched it failed (#2613, #2641, #2718, #2597). The sampled logs keep only the FAIL line, so which row drifted is not recorded. | 2 for a new inventory guard; the lasting fix is generating the inventory or splitting it into fragments, plus preflight against main + the PRs ahead (measure 1). |
| TestFullRowWriteGuard_PendingRowsNotExpired and TestChildParentLiveness_PendingRowsNotExpired, 18 Oct | Rows expiring 2026-10-18 turned red at 00:00 UTC on 19 Oct for every PR (#3365 and everything behind it). | 1: the date is evaluated nightly, warned 7 days ahead; PRs never see it. |
| TestNoRawErrorTextOnServerErrors, 17 Oct | The guard's PR (#3323, merged 04:05Z) exempted auth.go:InitSystem; #3340, open since the day before, made InitSystem send the standard body, so main + #3340 had a stale exemption row and #3340 failed in the queue. | 2: #3323's open-PR run over #3340's merge result would have failed and named it. |
| TestGeneratedStateMap_MatchesCommitted, 17 Oct | A drift guard for a generated file landed "red on main until the regen commit that follows"; PRs touching entrypoints that had not regenerated went red (#3388). | 2: report-only first day; the open-PR run lists PRs that must regenerate. |
| TestDirectLogAuditEventCallersAreSafe, 20 and 24 Oct | #3372 merged a migration seed tool that calls LogAuditEvent directly and main went red (#3341 failed behind it); on 24 Oct recordRecoveryKeyMismatch did the same (#3619). The guard had moved to internal/core/guards on 19 Oct (CACHE-GUARDS-1), so PR runs that select affected packages did not run it. | Not rule 1 or 2 (an old guard meeting a new caller): every repo-wide guard runs on every PR (MQ-ROUNDS-1, #3689) and preflight against main + the PRs ahead (measure 1). Rule 2 applies if a move or widening changes what a guard scans. |
| TestSecretFileReadsGoThroughOpenRegular, 13 and 23 Oct | The FIFO guard landed with #3178 (13 Oct 08:56Z) and was widened by #3187 (17:02Z) while #3162 was open; #3162 failed in the queue at 19:41Z. On 23 Oct a new staged-restore fsync open met the guard (#3583 failed; allowlisted next day). | 13 Oct: 2 (both #3178 and #3187 count as new, and their open-PR runs cover #3162). 23 Oct: an old guard meeting a new site, so guards on every PR (#3689) and measure 1. |
| Class C, guard-adjacent: full_row_write_repro_test.go `UpdateMachineIdentityCredential undefined` (7 Oct), ledger_fragments_test.go `readLedgerRows redeclared` (5 Oct) | A guard's repro test called a method another PR renamed; two ledger PRs added the same helper name to package core. | Not this contract: preflight against main + PRs ahead (measure 1). The open-PR run of rule 2 catches the repro case when the guard is the newer PR. |
