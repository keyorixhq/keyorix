### Internal
- **CI test-leg weights refreshed from a verbose run.** `scripts/ci-test-weights.tsv` was regenerated from the per-test times of a verbose dispatch run, so the shards of each sharded package end within about 2% of each other. Weights only: which test lands in which shard changes, never whether it runs.
