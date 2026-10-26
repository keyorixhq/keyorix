### Internal

- CI: in the merge queue, `docs_only` (and the other change classifiers) are now computed on the whole stack against the target branch instead of only the entry ahead, so the HEADGREEN batch rule cannot let a docs-only head skip jobs for a code entry below it. `docker-boot-smoke`, `helm-boot-smoke` and `demo-up-smoke` now skip on a docs-only change, and the two guard self-test steps of `adr-numbers` (about 9 of its 13 minutes) skip too.
