- **INV-AUTHZDIFF-every-inscope-op-covered-or-reasoned** Every mutating or
  secret-value-reading operation in `matrix.json` (REST route-template match, or
  gRPC RPC the op's leg actually calls) is either exercised by a bound op in
  `ops()` or carries an explicit uncovered reason (`fixture:`/`model:`/`design:`)
  in `coverage_reasons_test.go`. A new in-scope route or RPC therefore cannot
  silently go both uncovered and unexplained. When an op is newly bound, its
  reason is removed (the reason list shrinks), and `COVERAGE-ALL.md` is
  regenerated from the same derivation. Why: the "prefer the machine-checked over
  the asserted" principle (root `CLAUDE.md`), applied so the coverage frontier is
  derived from the type-checked route/RPC surface, not a hand-maintained list.
  Guard: `TestCoverageAllIsCurrent` and `TestCoverageIsCurrent` (regenerate +
  compare, report through `guardrules.Rollout`); `TestEveryOpBindsAMatrixRoute`
  (a bound op whose request matches no matrix route fails). Does NOT check that a
  bound op's authorization is *correct* — that is Oracle 2's job
  ([[INV-AUTHZDIFF-bound-op-gate-removal-red-proved]]) — only that the covered/
  reasoned partition is complete.
