# scripts/ci/guard-inputs.d/ — one ledger row per guard test

**New rows go here, not in `scripts/ci/guard-inputs.tsv`.** Each `*.tsv` file in this
directory holds exactly one row, in the same tab-separated format as the
legacy file (`file  globs  note`; see that file's header for what each column means).
Lines starting with `#` are allowed and ignored. Name the file
`<test file path with / replaced by __>.tsv` (e.g. `server__utc_write_guard_test.go.tsv`
for `server/utc_write_guard_test.go`) — the name is a convention, the reader enforces
uniqueness on the row's key (column 1), not on the file name.

Why: an append-only shared ledger makes every two PRs that add a row a
guaranteed merge conflict (in 14 days `guard-inputs.tsv` was touched by 22 PRs and sat
in 48 overlapping-PR pairs, the most of any file), and every new guard test must add a
row: `TestGuardInputsCoverSkippedPaths` fails a PR that adds a guard without one. A new
file cannot conflict with anyone else's new file.

Reader: `guardinputs.LoadMap` (`scripts/ci/guardinputs/main.go`) reads
`scripts/ci/guard-inputs.tsv` PLUS every `*.tsv` here, in sorted file-name order
(dual-read). Everything that uses the map sees the rows of both: `guardinputs select`
(`scripts/ci/run-input-guards.sh`, the docs-guards job), `TestGuardInputsCoverSkippedPaths`,
`TestGuardInputsMapIsLive` and `TestQuickStartChangeRunsTheDocsSecretsGuard`. It fails
on a fragment holding anything other than exactly one row, and on a key that appears
twice when at least one of the two copies is a fragment — so a fragment can never
silently shadow or duplicate a legacy row. Every other check applied to a legacy row
(3 columns, non-empty globs and note, a tracked `_test.go` file with Test funcs, every
glob matching a tracked file) applies to a fragment row unchanged.

The legacy file's existing rows are moved here by
`scripts/ledgers/migrate-to-fragments.sh`, which the coordinator runs once, in
a quiet merge window (it rewrites a file most open PRs touch). Do not run it
on a feature branch.
