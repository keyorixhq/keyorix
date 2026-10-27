# scripts/ci

Helpers used by CI workflows, or run locally next to them.

| Script | Run by | What it does |
|---|---|---|
| `failure-issue.sh` | scheduled workflows | Opens one GitHub issue per failing scheduled job, comments on repeat failures, and closes the issue when the job goes green. |
| `check-bug-origin-block.sh` | CI (`ci.yml`) | Checks that a `fix(...)` PR has filled in its "Bug origin" block (Introduced-by, Detected-by, Class, Severity). |
| `precheck-open-prs.sh` | the merge coordinator, **locally** | Rebases each listed open PR onto current `main` in a throwaway worktree and runs the checks that tend to fail only inside the merge queue. |
| `select-affected.py` | CI (`ci.yml`: `select`, on merge_group) | Merge-queue selection: from the entry's diff against `merge_group.base_sha`, the affected root-module packages (changed + importers), the test-suite legs that run, and the path gates of the heavy jobs. Full suite on go.mod/go.sum, `internal/testutil/**`, `ci.yml`, `scripts/ci/**`, the leg definitions or a generated-code input, and on any error. Pinned by `select_affected_test.go`. |
| `run-guards.sh` | CI (`ci.yml`: repo-guards, on every pull_request and on a selected merge_group run) | Every repo-wide guard, whatever the entry touches: the named guards (`*Guard`/`*Sweep`/`*Completeness`/`TestEvery*`/`TestNoRaw*`) and every source-scanning test in the root module, plus `global-guards.txt`. |
| `global-guards.txt` | `run-guards.sh` | The global guard package list, and the single source of it: the coordinator preflight (`~/proj/prompts/bin/preflight.sh`) reads it from the repo (the coordinator side is switched over after merge), so edit it only here. Every entry must exist as a directory; `global_guards_test.go` fails the PR on a typo, as `run-guards.sh` would fail the queue. |
| `run-input-guards.sh` | CI (`ci.yml`: docs-guards, every pull_request and merge_group run) | The guard tests whose non-Go inputs a change touched: every Go job skips a docs_only/web_only/go_unaffected/operator_only change, so a guard reading a Markdown file, `web/nginx.conf`, a script or `operator/` code runs here (#3616). Selects from `guard-inputs.tsv` via `guardinputs`; an unreadable change list runs every mapped guard. |
| `guard-inputs.tsv` | `run-input-guards.sh` | Guard test file -> the repo paths it reads (input globs, plus reviewed `!globs` it does not read). `guardinputs/guardinputs_test.go` fails a PR that adds a guard reading a path whose change alone runs none of its tests, and prints the globs to add: it runs ci.yml's real `changes` step for every such path and evaluates the jobs' own `if:` conditions. |
| `failfast-cancel.sh` | CI (`failfast-cancel.yml`, called by `ci.yml`'s `failfast-*` jobs on merge_group) | Merge-queue fail fast: after a job whose failure already fails the round, cancels every run still queued or in progress for that merge-group commit (ci.yml, CodeQL, ...), its own run last. Never touches another commit's runs and never fails its caller. Pinned by `failfast_cancel_test.go` against a recorded API response. |
| `check-no-attribution.sh` | CI (`no-attribution.yml`, on pull_request and merge_group), `.githooks/commit-msg` | Fails when a commit message in the PR range, the PR title or the PR body carries AI-assistant attribution (co-author or session trailers, "generated with" footers; `--patterns` lists them). Only messages and PR text are checked, never file contents. Offline tests: `check-no-attribution-test.sh` (also run by the workflow and by `no_attribution_test.go`). |
| `check-growth-guards.sh` (+ `growth_measure.py`) | `make check-growth` (locally; not yet wired into `ci.yml`) | Architecture-growth guard: fails when a package under `internal/` or `server/` has more than 260 non-test `.go` files or more than 44 transitive dependents in the module, naming the package and the overshoot. `--print` shows the worst packages, `--self-test` proves it fires. Baseline and reasoning: `docs/design/architecture-growth-baseline.md`. |
| `check-no-new-ledger.sh` | `make check-growth` (locally; not yet wired into `ci.yml`) | Warn-only (always exit 0): flags an existing ledger-shaped file (md/tsv/txt/conf/json/yaml/yml/csv/toml, not in the auto-resolve list) that a diff only appends to, more than 50 lines with none removed, and points at per-item fragments. `LEDGER_MAX_APPEND` overrides 50; `--self-test` proves it. Threshold evidence: `docs/design/architecture-growth-baseline.md`. |
| `install-gosec.sh` | CI (`ci.yml`: static-analysis, operator, cli, migrate) | Installs gosec in a throwaway module that also requires a newer `golang.org/x/tools`, so MVS picks that instead of gosec's own (older) requirement -- see the script header for why. |
| `retry-net.sh` | CI (`ci.yml`: licenses) | Runs a command and retries it (max 3 attempts, back-off) only when it failed on a transient network error from a remote proxy or registry (proxy.golang.org, Docker Hub); never on a go.sum mismatch or any other failure. Pinned by `retry_net_test.go` against real queue failure lines (`testdata/retry-net`). |

## Coverage floor on selected merge-queue runs

A selected merge-queue run does not compute the coverage floor: its skipped
legs produce no profile and its partial `root-N` legs cover a subset. A
coverage drop is therefore caught by the nightly full run on `main`, not by the
queue; the nightly failure issue names "coverage floor" as a possible cause
when `build-and-test` fails.

## precheck-open-prs.sh

Two PRs passed their own CI and then failed in the merge queue. The queue
tests against today's `main`, and the PR's own CI did not:

- **#2641**: after an audit API change landed on `main`, a benchmark the
  PR added ignored the new `error` return, so errcheck failed.
- **#2559**: a Postgres-only test asserted log text that the PR's own
  refactor had changed. Only the PG leg runs that test.

```sh
# one PR number per line; blank lines and '#' comments are ignored
printf '2641\n2559\n' | scripts/ci/precheck-open-prs.sh
scripts/ci/precheck-open-prs.sh --quick < prs.txt   # test-compile changed pkgs only

# lint must be the exact version CI pins (read from ci.yml); otherwise SKIP
GOTOOLCHAIN=go1.27.0 GOBIN=$HOME/bin go install \
  github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
GOLANGCI_LINT=$HOME/bin/golangci-lint scripts/ci/precheck-open-prs.sh < prs.txt

# the #2559 class: also run the changed packages' tests against Postgres
KEYORIX_TEST_PG_DSN='host=localhost port=5432 dbname=keyorix user=keyorix sslmode=disable password=…' \
  scripts/ci/precheck-open-prs.sh < prs.txt

scripts/ci/precheck-open-prs.sh --self-test         # red/green proof, no network
```

Example output:

```
PR     rebase    build  vet    lint                test-compile  pg       overall
2641   ok        ok     ok     FAIL                ok            not-run  FAIL
2559   ok        ok     ok     ok                  ok            FAIL     FAIL
2682   ok        n/a    n/a    n/a                 n/a           not-run  OK
```

A check that did not run never shows as `ok`. A missing or wrong-version
golangci-lint shows as `SKIP(lint-missing)` or `SKIP(lint-version)` and
makes that PR's overall verdict `INCOMPLETE`. Exit codes: `0` when every PR
is OK, `1` when any PR fails or conflicts, `2` when nothing failed but
something was skipped. Without a DSN the pg column shows `not-run`, which
is expected for this opt-in check and does not make the run incomplete.

The script never moves your checkout or any branch. Each PR is checked on a
detached HEAD in a `mktemp -d` worktree, and that worktree is removed on
exit or Ctrl-C. The script header covers the full method: how changed
packages map to the repo's several Go modules, why a replay conflict falls
back to a 3-way merge, how the test-compile timing was measured, and how it
relates to `scripts/git-write-guard.sh`.

## footprint-check.sh: the edge footprint tripwire

`scripts/ci/footprint-check.sh` keeps the edge advantage (small, light) from
regressing silently. It compares the release server binary, the CLI binary and
the idle peak RSS of a secure-baseline SQLite server (healthy, 30 s idle, run
3 times, the maximum is compared) with the limits in
`scripts/ci/footprint-budget.json`, and exits 1 with "current vs budget" for
every metric over its limit. Size limits are the measured value plus 10%, the
RSS limit the measured value plus 25% (the headroom absorbs run-to-run noise).

```
scripts/ci/footprint-check.sh                      # host platform: sizes + RSS
scripts/ci/footprint-check.sh --platform linux/arm64 --skip-rss   # cross-built sizes
scripts/ci/footprint-check.sh --print              # current values + suggested limits
scripts/ci/footprint-check.sh --self-test          # red/green proof the check fires
```

A missing size budget fails (fail closed). A `null` RSS budget (no baseline
measured on that platform yet) skips with a message, or fails under
`--require-rss`. RSS is only measured for the host platform. When growth is
intended, raise the limit in the PR that causes it and say why. It is
on-demand/nightly, not a merge-queue gate. It complements
`scripts/edge/footprint.sh` (server only, per build profile, four platforms):
that one has the air-gapped profile and the ARM targets, this one adds the CLI,
the secure baseline, the multi-run RSS protocol and a self-test.
