### Changed
- **CI: `fuzz-changed` runs once the quick CI of a PR head is green (MQ-LEVERS-1).**
  The three fuzz-changed jobs move from `fuzz-changed.yml` into `ci.yml` after
  `build-and-test`, keeping the check names (`fuzz-changed`, `fuzz (shard N)`). A newer
  push cancels the run with the rest of ci.yml, so fuzz shards no longer run on heads
  that already fail the quick tests. When `build-and-test` fails, is cancelled or is
  skipped, `fuzz-changed` is skipped.
