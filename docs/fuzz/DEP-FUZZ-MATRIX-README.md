# Dep-Fuzz Matrix — README

This document explains how to regenerate the dependency-to-fuzz-coverage matrix,
defines the REACH and FUZZ classes, and states explicitly what the matrix does
and does not verify.

## Regeneration

```sh
go run ./scripts/fuzzing/depmatrix
```

This regenerates both output files:
- `docs/fuzz/DEP-FUZZ-MATRIX.md` — human-readable table
- `docs/fuzz/dep-fuzz-matrix.json` — machine-readable JSON (schema version 1)

After regenerating, commit both output files and manually review
`docs/fuzz/DEP-FUZZ-GAPS.md` to see whether any UNTRUSTED+NONE rows changed.

The stale-check test (`TestDepFuzzMatrixNotStale` in
`scripts/fuzzing/depmatrix/depmatrix_test.go`) fails if the committed JSON
diverges from a fresh regeneration. Run after any change to go.mod, fuzz
targets, or repo imports.

## REACH classes

| Class | Meaning |
|-------|---------|
| `UNTRUSTED` | At least one non-test package that imports this module is reachable from an HTTP/gRPC handler, CLI input file, network client reading a remote reply, or a parser of imported/backup/config data. This is the highest-priority class for fuzz coverage. |
| `TRUSTED-ONLY` | Only fed data we generate ourselves (audit logs, local config, internal metrics). No known attacker-controlled input can reach this module's call sites. |
| `TOOLING` | Only imported by build-time tooling, test helpers, or `*_test.go` files. Never compiled into the production binary. |
| `UNUSED` | Not imported anywhere in the repo (neither production nor test code). Should not appear in the matrix after `go mod tidy`; if seen, check for stale go.mod entries. |

REACH is determined by a 1-hop import-graph walk from non-test source files.
It does not evaluate runtime wiring or build tags.

## FUZZ classes

| Class | Meaning |
|-------|---------|
| `DIRECT` | At least one `func FuzzXxx(f *testing.F)` in the repo imports this module directly (the fuzz file's own import list includes the module path). |
| `WRAPPED` | No fuzz file imports the module directly, but at least one fuzz file drives an own-module package that (in its non-test files) imports the module. 1-hop only. |
| `TARGETS.D` | The module appears in `scripts/fuzzing/targets.d/*.conf` but the import chain could not be verified statically (e.g. coverage via reflection or generated code). |
| `NONE` | No fuzz coverage found by any of the above methods. |

## What the matrix verifies

- Every direct dependency in every `go.mod` under the repo root is listed.
- Each dep's REACH class is derived from actual import-graph data (non-test `.go` files).
- Each dep's FUZZ class is derived from actual `func FuzzXxx` declarations and import lists.
- `TestDepFuzzMatrixNotStale` fails (red) when the committed JSON diverges from
  a fresh run, ensuring the matrix is kept current.
- `TestDepFuzzMatrix_GoModAddGoesRed` proves that adding a new direct dep to
  `go.mod` causes the stale-check to fire: `parseGoModDirect` detects the new
  require line, so the regenerated rows differ from the committed file.

## What the matrix does NOT verify

- **Oracle quality**: a no-panic oracle and a differential oracle both appear
  as DIRECT or WRAPPED. The matrix does not distinguish them.
- **Transitive coverage**: WRAPPED covers 1 hop only. A chain of
  `fuzz → ours → ours → dep` is not detected.
- **Build-tag exclusions**: files with `//go:build ignore` are skipped, but
  other build constraints are not evaluated.
- **Compilation or execution**: fuzz targets are not compiled or run by the
  matrix generator. A target that fails to compile is still counted as DIRECT.
- **Runtime wiring**: UNTRUSTED means the import graph reaches an
  attacker-influenced call site in some deployment configuration. It does not
  mean every deployment exposes the dep to untrusted input.
- **Indirect dependencies**: only direct `require` lines (without `// indirect`)
  are listed. A transitive dep not explicitly required is not in the matrix.
- **Coverage depth**: DIRECT means a fuzz function exists and imports the dep.
  It says nothing about whether the fuzz corpus is large, whether the harness
  stresses interesting code paths, or whether the CI fuzz budget is sufficient.
- **Own-module deps**: modules whose path matches an own repo module (e.g. a
  `replace` directive pointing to `../`) are excluded from the matrix.

## Schema (dep-fuzz-matrix.json)

```json
{
  "schema_version": "1",
  "root_module": "github.com/keyorixhq/keyorix",
  "counts": {
    "total": 75,
    "by_reach": { "UNTRUSTED": 48, "TRUSTED-ONLY": 12, "TOOLING": 15, "UNUSED": 0 },
    "by_fuzz":  { "DIRECT": 62, "WRAPPED": 6, "TARGETS.D": 0, "NONE": 7 },
    "untrusted_none": 3
  },
  "rows": [
    {
      "module":       "cloud.google.com/go/kms",
      "version":      "v1.36.0",
      "go_mod":       "go.mod",
      "import_count": 1,
      "top_pkgs":     ["internal/connect/gcpkms"],
      "reach":        "UNTRUSTED",
      "fuzz":         "DIRECT",
      "evidence":     ["fuzz/thirdparty/gcpkms/hostile_gcpkms_test.go:FuzzGCPKMSDecrypt"],
      "notes":        ""
    }
  ]
}
```

`import_count` is the number of **non-test** packages in the repo that import
the module. `top_pkgs` lists up to 3 of them alphabetically. `evidence` lists
up to 3 fuzz targets (file path and function name) that cover the dep.
