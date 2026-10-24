# scripts/refactor: proof and measurement tools for the internal/core split

ADR-121 (`docs/adr-121-core-package-split.md`) asks every extraction PR for a proof
bundle. These are the tools; their output goes in the PR body.

| Tool | What it answers |
|---|---|
| `go run ./scripts/refactor/provemove -base <tree> -head <tree> -dirs <old,new> [-strip core -pkgmap coretests=core -rename a=A]` | Did the PR only move declarations? Prints `PURE MOVE: N declarations identical` or the CHANGED/MISSING/ADDED keys. Doc comment in `provemove/main.go` lists what it does not check. |
| `go run ./scripts/refactor/coretestclass [-relax storage,now] [-out dir]` | Which in-package test files of `internal/core` are black-box (helper closure included), and which of those may move in a wave (fuzz, testdata, Postgres, registry, source-scan and ledger-cited files excluded). |
| `scripts/refactor/measure-core.sh [--importers]` | The before/after tables: build-cache archive sizes and the test-side counts with 30-day edits. |

Making the two trees for `provemove`: `git worktree` does not work in sandboxed sessions, so
export them, for example `mkdir ../base && git archive <merge-base> | tar -x -C ../base`
and the same for the PR head.

## Not ported

The CORE-SPLIT-DESIGN-1 analysis also used a `go/packages` symbol graph (`symgraph`) and
Python analyses (strongly connected components, cluster seams, churn, merge-queue leg
replay, fan-out) from `raw/core-split-design-1-scripts.tgz` in that session's workspace.
They were one-off design measurements, larger than this directory should carry, and the
archive was no longer on disk when the guards session (CORE-SPLIT-GUARDS-1) ran, so they are
not here. `coretestclass` re-implements the black-box classification the move briefs need;
its counts on main matched the design's within a few files.
