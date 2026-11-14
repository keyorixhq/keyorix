# Open-issue audit, 2026-11-14, second batch (ISSUE-AUDIT-NOV-3)

Same method as ISSUE-AUDIT-NOV-1 (`docs/design/issue-audit-2026-11.md`, #4204): an open issue is checked
against `origin/main`, and the verdict says whether the issue is still true. This batch covers storage,
ops, perf, crypto and test-gap issues.

Base: `origin/main` at `d09d733903e7` (fresh `kclone`, `ktree origin/main` clean). Read-only audit: no
production code is changed by this PR.

Verdicts:

- **FIXED**: the code on `origin/main` does what the issue asks. Evidence is a file:line or a test name.
- **OPEN**: the defect or gap is still on `origin/main`, with a one-line repro or the owner. `OPEN (IN PR #N)`
  means a fix exists in an open PR and is not on `origin/main`.
- **NEEDS DECISION**: the code cannot settle it. The question is stated for the coordinator or Andrei.

Tests quoted as "pass" were run on this tree with `~/.claude/scripts/gotest.sh` (tree `d09d733903e7`, clean),
and were checked to have run, not skipped. Tests marked "not run" were read, not run.

## Group 1: locking and storage races

| Issue | Verdict | Evidence | Note |
|---|---|---|---|
| #4210 UpdateLegalHold is an unconditional Save; a stale `released=false` struct reverts a concurrent lift | OPEN (queued) | Not checked, on purpose: STORE-STALE-NOV-2 is queued for it. | Owner: STORE-STALE-NOV-2. Nothing to add here. |
| #3225 `REST POST /api/v1/users/` WithTransaction#1 effect-then-error commits the user with no audit event | OPEN (IN PR #4208) | The fix is in open PR #4208 (`internal/core/users.go`, `server/faultops/partial_commit_user_create_test.go`, head `068e71ed6c9f`, mergeable). It is not on `origin/main`. | Not re-run on main: the replay input from the issue (`REPLAY_HEX=05972b3232`, `TestReplayStorageFaultInput`) needs the `server/faultops` package and the PR owns that proof. Close after #4208 merges. |
| #2887 DeleteProjectIfEmpty counts before taking the project lock | FIXED | Verified in #4204 (Group 1, same file path `internal/storage/store/local_secrets.go`). Skipped here as asked. | See `docs/design/issue-audit-2026-11.md`. |
| #3464 (a) Credential lookup GORM fallback: no test confirmed to reach it | FIXED | Two tests reach it. `TestCredentialLookup_GORMFallbackAnswersAsTheRawPath` (`internal/storage/store/credential_lookup_fallback_test.go:93`) forces both fallback branches (a transaction-scoped store, where `rawStmts` is nil, and a failed prepare), proves from the statement log that the GORM query answered, and requires the same row and the same not-found error text as the raw path. `TestCredentialLookup_TxScopedFallback` (`internal/storage/credential_lookup_fallback_test.go:47`) does it through the factory, whose migration adds the unknown extra column under `-tags nplus1`. Both pass here (SQLite; the store test has only a `sqlite` subtest). Commit `0a40f010b` (item 4 of the #3464 session). | The issue's "mutation-check it" is met without editing production code: `TestCredentialLookup_FallbackComparisonCatchesABrokenFallback` (same file, line 175) feeds deliberately broken copies of the fallback query through the same comparison and requires them to be told apart. It passes. I did not run my own mutation of `local_machine_credentials.go`. |
| #3464 (b) CI has no step running `go test -tags nplus1 ./internal/storage/...` | NEEDS DECISION | `rg --hidden nplus1 .github scripts Makefile` finds nothing, and the only build tags in `.github/workflows` are `noaws,noazure,nogcp` (release dry run), `e2e`, and nuclei's template tags. With the tag, `TestCredentialLookup_TxScopedFallback` also passes here (`go test -tags nplus1 ./internal/storage/ -run TestCredentialLookup_TxScopedFallback`); I ran only that test with the tag, not the package. | Without the tag the same test still runs in CI's plain `go test -race ./...`, so the fallback is covered; what the tag adds is the unknown extra column on every table (`factory_nplus1_hook.go`), i.e. the rolling-upgrade case of `docs/rolling-upgrade-columns.md`. Question for Andrei: add a `-tags nplus1` step for `./internal/storage/...` to a `.github` workflow, or accept the plain run as enough? This session may not edit `.github`. |
