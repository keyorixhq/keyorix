# docs/atomicity-exempt.reviewed.d/ — review sidecar for docs/atomicity-exempt.tsv

One file per ledger row, holding exactly one tab-separated line:
`key  added_by  reviewed_by`, where `key` is the ledger row's first column.
Lines starting with `#` are ignored. Name the file after the key with `( ) *`
dropped and `:` turned into `__` (e.g. `AUDIT__KeyorixCore.RevokeLease.tsv`);
the name is a convention, the reader matches on the key.

Checked by `TestExemptLedgers_EveryRowIndependentlyReviewed`
(internal/core/guards/exempt_ledger_review_test.go): every ledger row needs a
row here, `reviewed_by` must be non-empty and differ from `added_by`, and a row
here whose key is no longer in the ledger fails. A new ledger row is therefore
red until someone other than its author adds its file here.

Fragments, not one flat file, because a shared flat list breaks the merge queue
for PRs that are green alone (single_file_allowlist_guard_test.go,
GUARD-COLLISION-NOV-1). Not new ledger columns, because several readers parse
the ledger's three columns (internal/core/guards, server/faultops,
internal/statemap).

REVIEW-4543-DEEP-1 (2026-11-21, #2693, PR #4543): every row was re-read
against the code by a review session independent of the row authors. It
checked 9 rows itself and the other 38 through one read-only sub-agent, and it
re-checked the sub-agent's disputes. It concurs with all 47 rows as they read
after its two corrections (VerifyMFACredentials, finalizeAccessRequestApproval).
Corrections, reclassifications and stale-row notes are recorded in the ledger
row's own reason, prefixed "#2693 review".
