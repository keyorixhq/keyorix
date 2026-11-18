### Added

- `scripts/fuzzing/depmatrix/`: Go generator that produces a deterministic
  dependency-to-fuzz-coverage matrix from static import-graph analysis.
  Running `go run ./scripts/fuzzing/depmatrix` regenerates
  `docs/fuzz/DEP-FUZZ-MATRIX.md` (human-readable) and
  `docs/fuzz/dep-fuzz-matrix.json` (machine-readable, schema v1).
- `docs/fuzz/DEP-FUZZ-MATRIX.md` and `docs/fuzz/dep-fuzz-matrix.json`:
  initial matrix for 75 direct dependencies — UNTRUSTED=48, TRUSTED-ONLY=12,
  TOOLING=15, UNUSED=0, DIRECT=62, WRAPPED=6, NONE=7, gaps
  (UNTRUSTED+NONE)=3.
- `docs/fuzz/DEP-FUZZ-GAPS.md`: gap analysis for UNTRUSTED+NONE rows, with
  risk ranking and suggested fuzz targets.
- `docs/fuzz/DEP-FUZZ-MATRIX-README.md`: class definitions, regeneration
  instructions, and an explicit list of what the matrix does not verify.
- `scripts/fuzzing/depmatrix/depmatrix_test.go`:
  `TestDepFuzzMatrixNotStale` (byte-compare stale-check) and
  `TestDepFuzzMatrix_GoModAddGoesRed` (red/green proof that a new `go.mod`
  direct dep triggers the stale-check).
