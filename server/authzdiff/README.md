# server/authzdiff

Test-only cross-layer authorization differential harness. See `MATRIX.md`,
`COVERAGE.md`, `COVERAGE-ALL.md` and `OUTCOMES.md` for the generated and
reference material.

## Regenerating the generated files

`matrix.json` and `MATRIX.md` are generated from the type-checked source;
`COVERAGE.md` and `COVERAGE-ALL.md` are generated from `matrix.json` and the
ops in this package. After adding or removing a route or gRPC method, or
changing a REST gate, regenerate them in this order:

```
go run ./devtools/authzmatrix -md server/authzdiff/MATRIX.md -json server/authzdiff/matrix.json
AUTHZDIFF_REGEN_COVERAGE=1 go test ./server/authzdiff -run 'TestCoverageIsCurrent|TestCoverageAllIsCurrent'
```

(`GOFLAGS=` if your environment adds `-trimpath`.) When a merge conflicts on
one of these files, take either side and regenerate rather than hand-merging.
A new in-scope operation that the harness does not cover needs a reason in
`coverage_reasons_test.go`.

`TestMatrixKeysAreCurrent`, `TestCoverageIsCurrent`, `TestCoverageAllIsCurrent`
and `TestGlobalHandlerFlagMatchesRouter` report through `guardrules.Rollout`
(`docs/guard-rollout-contract.md`).
