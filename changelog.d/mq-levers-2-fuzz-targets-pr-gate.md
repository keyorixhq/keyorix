### Internal
- **`fuzz-targets` now runs on pull requests that add, remove or re-tag a Fuzz function.** It used to run only in the merge queue, so a PR that added `func FuzzX` without its `scripts/fuzzing/targets.d` conf was green on FAST and failed the queue. The required context name is unchanged and a PR touching none of those paths still skips it. Guarded by `scripts/ci/fuzz_pr_gate_test.go`.
