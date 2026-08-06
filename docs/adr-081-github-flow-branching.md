# ADR-081: GitHub Flow branching and merge model

## Status

Accepted, as-built. Backfill ADR — trunk-based GitHub Flow has been the working
model since before the ADR series started; the LTS/`release/X.Y.x` amendment in
ADR-067 is the one place it has since been deliberately narrowed. Recorded now per
the M2 "ADR backfill" backlog item.

## Context

A solo-founder-plus-agents project with a high commit cadence (main has taken on
the order of 1,500 commits total, with roughly 750 in a recent 30-day window per
ADR-067's own count) needs a branching model that stays out of the way rather than
adding process overhead a small team can't sustain — no separate `develop`
integration branch to keep in sync, no release-branch cutting ceremony for every
version, and a merge path simple enough that CI can gate it unambiguously.

The alternative most explicitly not chosen — GitFlow (long-lived `develop`,
`release/*`, `hotfix/*` branches with scheduled merge-backs) — was never adopted
and is not discussed in any doc as a rejected option; there is no contemporaneous
record of a GitFlow-vs-GitHub-Flow debate. This ADR states the as-built model
directly rather than reconstructing a decision debate that left no paper trail.

## Decision

**Single trunk: `main`, no `develop`/`release`/`staging` branch.** Every CI
workflow (`ci.yml`, `codeql.yml`, `sonarcloud.yml`, `trivy.yml`, `semgrep.yml`,
`web-ci.yml`, `scorecard.yml`, `dco.yml`, `osv-scanner.yml`) triggers only on
`push`/`pull_request` against `branches: [main]` — no workflow references any other
long-lived branch. Feature work happens on short-lived branches (or, for
Claude-Code-driven parallel sessions, git worktrees under `.claude/worktrees/` —
an operational convention layered on top of this model, not itself part of the
branching decision) merged back to `main` via PR.

**Branch protection is real, not aspirational.** `CONTRIBUTING.md` states it
directly: "Open a PR against `main`. CI must pass in full before it can merge
(branch protection enforces this — there's no bypass, including for maintainers)."
Eleven required checks gate every merge (go vet/build/test, gosec, golangci-lint,
govulncheck, gitleaks, CodeQL, Helm lint/kubeconform, checkov, go-licenses, per
`CONTRIBUTING.md`'s own enumeration). `.github/CODEOWNERS` scopes mandatory review
to security-sensitive paths (crypto, auth, middleware, storage migrations, CI
workflow files themselves).

**Squash-merge is the merge strategy** — `CLAUDE.md`'s git conventions section
notes this explicitly in the context of PR trailers ("squash-merge folds commit
trailers into the PR's merge commit"), which is also why that same doc forbids
`Co-Authored-By: Claude` trailers on commits: a trailer on any commit in a
multi-commit PR branch survives into the single squashed merge commit on `main`.

**Releases are tag-based, not branch-based**, layered on top of the trunk model:
`docker-publish.yml` and `release.yml` both trigger on `push: tags: ['v*']` — no
release-cutting branch, just a tag on a commit already on `main`.

**The one deliberate amendment to pure trunk-based development** is ADR-067's LTS
policy: designated LTS releases every 18–24 months get a `release/X.Y.x`
maintenance branch, fixed forward-only via cherry-pick and **never merged back into
`main`**. This is a narrower, later addition on top of the model this ADR
describes, not a contradiction of it — `main` remains the only branch normal
feature work ever targets; `release/X.Y.x` branches exist solely to receive
backported security fixes for a line no longer receiving new features. See
ADR-067 for the full support-line policy; this ADR is the trunk-model foundation
it builds on.

## Consequences

- **Positive.** No integration-branch drift to manage, no release-branch cutting
  ceremony for ordinary releases, and a merge-to-`main` path that CI can gate
  unambiguously (one branch, one required-checks list). This has scaled to a high
  commit cadence and many concurrent worktree-based agent sessions without process
  overhead growing to match.
- **Negative / accepted tradeoff.** Every merged PR ships to `main` immediately —
  there is no integration branch to catch a defect before it reaches the branch
  release tags are cut from. This is mitigated, not eliminated, by the eleven
  required CI checks and by ADR-067's LTS lines existing specifically to give
  long-term customers a branch that doesn't take ongoing `main` churn.
- The `release/X.Y.x` amendment (ADR-067) means this is no longer *pure* GitHub
  Flow in the strictest sense once an LTS line exists — worth stating plainly here
  so a future reader doesn't find the two ADRs in apparent tension. They aren't:
  ADR-067 narrows this ADR's model for a specific, bounded case (long-term security
  support) without changing how ordinary feature work flows through `main`.
