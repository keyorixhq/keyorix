# docs/adr-conformance-enforced.d/ — one ledger row per file

**New rows go here, not in `docs/adr-conformance-enforced.tsv`.** Each `*.tsv` file in this
directory holds exactly one row, in the same tab-separated format as the
legacy file (`claim_id  package  proving_test  verification  landed_commit  issue  note`; see that file's header for what each column means).
Lines starting with `#` are allowed and ignored. Name the file
`<claim_id>.tsv` — the name is a convention, the reader enforces uniqueness on the
row's key (column 1), not on the file name.

Why: an append-only shared ledger makes every two PRs that add a row a
guaranteed merge conflict (2026-10-03/04: about 20 approved PRs fell out of
the merge queue, mostly on ledgers like this one). A new file cannot conflict
with anyone else's new file.

Reader: `scripts/check-adr-conformance.sh` reads `docs/adr-conformance-enforced.tsv` PLUS every `*.tsv` here
(dual-read). It fails on a fragment holding anything other than exactly one
row, and on a key that appears twice when at least one of the two copies is a
fragment — so a fragment can never silently shadow or duplicate a legacy row.
Every other check the reader applies to a legacy row applies to a fragment
row unchanged.

The legacy file's existing rows are moved here by
`scripts/ledgers/migrate-to-fragments.sh`, which the coordinator runs once, in
a quiet merge window (it rewrites a file most open PRs touch). Do not run it
on a feature branch.
