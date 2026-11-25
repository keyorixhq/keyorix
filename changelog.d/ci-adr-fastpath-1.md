### Changed

- CI: a pull request or merge-queue group that changes only numbered ADRs (`docs/adr-NNN-*.md`) and `changelog.d/` fragments no longer runs the Go-based steps of the `adr-numbers` job (the two ledger verifications, the review-coverage check and the Go setup), cutting that job from about 7 minutes to under 1 minute; any other changed file runs them as before, and `scripts/ci/guardinputs` fails if a ledger test starts reading ADR text.
