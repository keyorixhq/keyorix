### Testing

- **Finding re-fuzz gate (AI-T3).** `scripts/fuzzing/finding-regate/regate.py`
  maps a git diff to KFZ findings whose fuzz targets cover the changed packages,
  then replays committed seed-corpus entries (`go test -run 'FuzzXxx/seedname'`)
  and runs a bounded burst (`go test -fuzz` default 60 s) for each matched target.
  Exits non-zero on any replay failure or burst crash; prints "no findings touch
  this diff" and exits 0 when nothing matches.  32 unit tests with fake runner
  fixtures provide red/green proofs for planted regression, clean repair, empty
  diff, and missing-seed loud-failure cases.  Design and two CI variants (private
  registry / merge-queue-only vs. public-safe export / every push) documented in
  `docs/fuzzing/finding-regate.md`; proposed workflow at
  `docs/fuzzing/finding-regate.workflow.yml.proposed`.
