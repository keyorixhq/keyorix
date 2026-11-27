### Testing

- `scripts/fuzzing/depmatrix/`: generator for a dependency-to-fuzz-coverage
  matrix (reach class and fuzz class per direct dependency, from import-graph
  analysis). `go run ./scripts/fuzzing/depmatrix` writes it to `.scratch/depmatrix/`;
  the matrix is generated on demand and not committed.
- Gap guard: every dependency reachable from untrusted input that has no fuzz
  target needs a one-row fragment in `docs/fuzz/dep-fuzz.d/` (module, expiry,
  reason). `TestDepFuzzGaps_EveryOpenGapIsExempt` and
  `TestDepFuzzGaps_NoStaleOrDuplicateExemption` compare the live derivation with
  the fragments and ignore versions and import counts, so dependency bumps do not
  affect them. They are report-only on pull requests until promoted
  (`docs/guard-rollout.d/`).
- `docs/fuzz/DEP-FUZZ-GAPS.md` and `docs/fuzz/DEP-FUZZ-MATRIX-README.md`: the
  2026-11-19 gap analysis and the class definitions, including what the matrix
  does not verify.
