### Changed
- CI: a manual `workflow_dispatch` run of the CI workflow can set `verbose_tests=true` to run the test-suite legs with `go test -v`, so job logs carry per-test timings for `scripts/ci/gen-test-weights.py`. Other events are unchanged.
