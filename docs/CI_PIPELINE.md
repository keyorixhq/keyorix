# CI pipeline engineering notes

A working catalog of patterns behind this repo's own GitHub Actions CI (not
to be confused with [`CI_CD.md`](CI_CD.md), which is about consuming Keyorix
secrets in *your* pipeline). Written after a round of CI-efficiency work
across `.github/workflows/ci.yml`, `codeql.yml`, `trivy.yml`,
`docker-publish.yml`, `web-ci.yml`, `sonarcloud.yml`, `dast.yml`,
`release.yml`, and `anchore-syft.yml` (9 merged PRs). Every claim below
traces to a merged PR and a real verification step — a branch-protection API
call, a source read of a pinned action, an actionlint run, or a real CI
failure. Where something was tried and reverted, that's included too: the
failure is as load-bearing as the fix.

## 1. Diff-aware job skipping

The highest-leverage pattern here. A PR touching only five Markdown ADR
files was still triggering the full 8-way-sharded Go test matrix, static
analysis, lint, CodeQL, and Helm chart validation — nothing in that diff
could change any of those outcomes. The fix is a `changes` job at the top of
`ci.yml`/`codeql.yml` that inspects the PR's file list once and emits
boolean flags every expensive job then gates on via job-level `if:`.

```yaml
# One job, computed once, consumed by every downstream job
changes:
  outputs:
    docs_only: ${{ steps.filter.outputs.docs_only }}
    go_unaffected: ${{ steps.filter.outputs.go_unaffected }}
    operator_only: ${{ steps.filter.outputs.operator_only }}
  steps:
    - id: filter
      run: |
        changed=$(gh api "repos/${{ github.repository }}/pulls/${{ github.event.pull_request.number }}/files" \
          --paginate --jq '.[].filename')
        # allowlist match: every changed file must fall inside the safe set
        if [ -z "$changed" ] || echo "$changed" | grep -vE '^(scripts/|\.semgrep/|demo/|...)' > /dev/null; then
          echo "go_unaffected=false" >> "$GITHUB_OUTPUT"
        else
          echo "go_unaffected=true" >> "$GITHUB_OUTPUT"
        fi

# every job that can't be affected gates on the flag
test-suite:
  needs: [changes]
  if: needs.changes.outputs.docs_only != 'true' && needs.changes.outputs.go_unaffected != 'true'
```

### The one rule that makes this safe

**Allowlist, never denylist.** Define what's *provably* safe to skip (a
narrow, verified set: docs, scripts, rule-config YAML, root metadata files)
— not what's unsafe. A denylist (`skip unless it touches internal/, cmd/…`)
fails dangerously: add a new top-level directory later and forget to update
the filter, and it silently falls outside the denylist and skips tests it
should have run. An allowlist fails safe — an unrecognized new directory
just means the full suite runs unnecessarily.

### The mistake this prevents

`paths-ignore` on the workflow trigger looks like the obvious fix and is the
wrong one whenever a gated job is a **required branch-protection status
check**. A workflow that never triggers produces *no check-run at all* —
GitHub shows the PR permanently stuck on "required check pending," because a
check that never runs can never satisfy the requirement. A job skipped via
job-level `if:` still reports a check-run with conclusion "skipped," and
branch protection treats that as satisfying the requirement. Verify which
mechanism is safe by *calling the branch-protection API directly* — don't
infer it from a code comment or assume:

```bash
gh api repos/OWNER/REPO/branches/main/protection \
  -q '.required_status_checks.contexts'
```

One workflow's own comment claimed a job named "CodeQL" was required; the
API said it wasn't (only its two per-language legs were). Comments drift
from reality — the API doesn't.

### Flags aren't interchangeable across jobs

A second module in the repo (a separate `go.work`-excluded operator
package) needed its own flag, `operator_only`, and the two flags compose
*differently per job*:

| Job | Skips on `go_unaffected` | Skips on `operator_only` | Why |
|---|---|---|---|
| root test suite | yes | yes | an operator-confined diff can't touch the root module |
| operator's own job | yes | **no** | this is exactly the job that must still run |
| license check | yes | **no** | checks both modules' deps — operator-only could add one |
| Helm chart lint | yes | yes | no chart file lives under the operator module's own tree |

Treat each new flag as a claim ("this diff cannot affect X") and check it
job by job — copying one job's gate onto another without rechecking the
claim is how a skip becomes a false negative.

### A matrix job can't use a per-leg condition

A CodeQL job matrixed over `[server, operator]` needed the server leg to
additionally skip on `operator_only` while the operator leg must not. The
natural-looking fix —

```yaml
if: needs.changes.outputs.operator_only == 'true' && matrix.name == 'server'
```

— fails actionlint outright: `context "matrix" is not allowed here`.
Job-level `if:` is evaluated once, before the matrix expands. The fix was
splitting the matrix into two explicit jobs (`analyze-server`,
`analyze-operator`), each with its own condition, preserving the exact
`name:` values so branch protection kept matching the same two
required-check names. Verified with actionlint before and after — this is
exactly the kind of thing that looks fine until the linter (or a real run)
says otherwise.

## 2. Cache every pinned, deterministic tool download

Applies almost everywhere security-scanning workflows accumulate "curl a
release tarball" steps over time. Four tools in `ci.yml` — `actionlint`,
`gitleaks`, `kubeconform`, `checkov` — downloaded fresh via `curl` +
`tar`/`unzip` on every single run, while three sibling tools in the same
file (`govulncheck`, `gosec`, `go-licenses`) already used `actions/cache`.
Same repo, same convention half-applied. All seven are already
version-pinned with a checksum, which is exactly what makes them safe,
deterministic cache keys.

```yaml
- name: Cache actionlint binary
  uses: actions/cache@<pinned-sha>
  with:
    path: actionlint
    key: actionlint-${{ env.ACTIONLINT_VERSION }}-${{ runner.os }}

- name: actionlint
  run: |
    if [ ! -x ./actionlint ]; then
      curl ... | sha256sum -c - && tar -xz ...
    fi
    ./actionlint
```

Two variants worth naming explicitly, since they don't fit the simple guard
above:

- **Tool adds itself to `$GITHUB_PATH`** — the PATH-append line must run
  every time, cache hit or miss. `$GITHUB_PATH` is a per-run ephemeral file,
  not something a cache restores.
- **Playwright's `--with-deps`** — caching the browser binary directory
  doesn't cover the apt-installed system libraries that flag also pulls in.
  A cache hit should still run a cheap, idempotent `install-deps`-only pass,
  not skip setup outright.

**Check the default before "fixing" it.** `actions/setup-go` has cached the
Go module + build directory by default since its `cache` input defaulted to
`true` — every job using it already benefits without any extra config.
Confirmed by reading the action's own `action.yml` rather than assuming;
this is the number one thing to check before proposing Go build caching as
a fix, since it's often already solved.

## 3. Read the third-party action's source before patching around it

The SonarCloud case: a proposed fix turned out to already exist one layer
down. The plan was to add `actions/cache` for the SonarCloud scanner CLI.
Reading the pinned action's `action.yml` first (not assumed) surfaced two
things: the action in use, `SonarSource/sonarcloud-github-action`, prints a
deprecation warning on *every run* and is a thin wrapper around
`SonarSource/sonarqube-scan-action` — which already has its own
`actions/cache` step for exactly the scanner CLI, baked into the composite
action itself.

The real fix was migrating to the non-deprecated action directly (its own
docs call it a "drop-in replacement"), not adding a redundant cache on top
of one that already existed two layers down. This is a "verify, don't
assume" habit as much as a specific fix: any time an optimization targets
behavior inside a third-party action, read that action's own source at the
pinned ref first.

## 4. A caution: verifying via source isn't the same as verifying via a run

Included because the failure is exactly as instructive as the successes
above. `trivy.yml` ran the identical filesystem misconfig scan **twice** —
once to produce a SARIF upload with no exit-code (so it could never fail the
job), once with `exit-code: 1` for the actual gate. `format` and
`exit-code` looked like independent options on paper, and reading the
action's `entrypoint.sh` confirmed they're both just separate environment
variables passed to one underlying scanner invocation — so merging the two
steps into one looked safe.

**What actually happened:** this repo's Helm charts fail to render without
`--set` overrides supplying required values — expected, since this scan
targets the whole filesystem, not one rendered chart with test values. The
scanner logs that as an error either way. With the default table formatter,
that error is a logged warning; the run continues and passes. With the
SARIF formatter, the *same* error propagates into a hard non-zero exit with
no findings printed at all — a different code path inside the tool, not
documented, not visible from reading the wrapper script.

The fix was reverting to two steps, with a comment on the reverted code in
`trivy.yml` explaining exactly this, so the same "obvious" merge doesn't get
re-attempted blind by someone who only reads the entrypoint script the way
the first attempt did.

> **The transferable lesson:** reading a tool's source to confirm two
> options are independent CLI flags is necessary. It is not sufficient when
> the tool has format-specific internal handling that the entrypoint script
> doesn't surface. Any merge of two previously-separate invocations needs a
> real CI run before it's considered done — and if it breaks, revert
> immediately and document why, rather than iterate on guesses against a
> red build.

## 5. Trigger-scope details worth checking, not assuming

**`paths-ignore` and tag pushes.** `docker-publish.yml` triggered on every
push to `main` *and* on `v*` tags, with no path filter — a docs-only merge
still built, signed, and pushed five container images. Adding
`paths-ignore` to a trigger that also matches tags raised an obvious
question: could a real release tag get silently skipped if its underlying
commit happened to look docs-only?

GitHub's own documentation settles it directly: *"Path filters are not
evaluated for pushes of tags."* A `paths-ignore` on a combined `branches` +
`tags` trigger only ever constrains the branch case. Checked before
shipping, not after.

## Applicability checklist for another Go project

Roughly in order of payoff-to-effort. Nothing here is universal — check each
claim against the target repo before porting it.

- [ ] Does the required-checks list actually match what the workflow file
      implies? Run the branch-protection API call above before choosing
      `paths-ignore` vs. job-level `if:` for any given job.
- [ ] Is there a repo-wide "diff shape" (docs-only, single-module-only,
      frontend-only) that recurs often enough to be worth a `changes` job?
      If the repo is single-module with no docs-heavy contribution pattern,
      this pattern's payoff shrinks a lot.
- [ ] Grep every workflow for `curl.*-fsSLO` or similar raw downloads and
      check whether each is already version-pinned (a prerequisite for safe
      caching) and whether a sibling tool in the same file already shows the
      right `actions/cache` pattern to copy.
- [ ] Confirm `actions/setup-go`'s cache is actually active (default true
      since a few major versions back) rather than proposing to add it.
- [ ] For any SonarCloud/SonarQube workflow, check whether it still uses the
      deprecated `sonarcloud-github-action` wrapper — same migration applies
      verbatim.
- [ ] For any workflow duplicating a scan for SARIF-vs-blocking reasons,
      don't merge them without a real CI run, even if the tool's docs say
      the two options are independent.
- [ ] Any workflow triggered on both branch and tag pushes can safely take
      `paths-ignore` for the branch case with zero risk to tag-triggered
      releases — this is documented GitHub behavior, not repo-specific.
