# Dep-Fuzz Matrix — README

This document explains how to regenerate the dependency-to-fuzz-coverage matrix,
defines the REACH and FUZZ classes, and states explicitly what the matrix does
and does not verify.

## Regeneration (on demand; the matrix is not committed)

```sh
go run ./scripts/fuzzing/depmatrix
```

This writes two files under `.scratch/depmatrix/` (git-ignored):
- `DEP-FUZZ-MATRIX.md` — human-readable table
- `dep-fuzz-matrix.json` — machine-readable JSON (schema version 1)

Every column is derived from the go.mod files, the imports and
`scripts/fuzzing/targets.d`, so nothing derived is committed: a committed copy
goes stale on every dependency bump or new import. Use `-out-md` / `-out-json`
to write elsewhere (for a nightly artifact).

## The gap guard (what is committed and tested)

The one thing a person decides is why a dependency that is reachable from
untrusted input (`UNTRUSTED`) has no fuzz target (`NONE`) yet, and until when.
That is a fragment, one file per module: `docs/fuzz/dep-fuzz.d/<module with "/"
replaced by "__">.tsv` holding one row, `module<TAB>expires<TAB>reason`
(YYYY-MM-DD; lines starting with `#` are comments).

`scripts/fuzzing/depmatrix/depmatrix_test.go` derives the live matrix and fails
when

- an `UNTRUSTED` + `NONE` dependency has no fragment (add a fuzz target or a
  fragment);
- a fragment names a dependency that is no longer an open gap (fuzzed, removed
  or no longer reachable; delete the fragment);
- two fragments name one module; or
- a fragment's expiry is malformed, or (nightly run only) has passed.

It reads only each row's module, reach and fuzz columns, so a version bump, a
changed import count or a new import of a known module cannot fail it.

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
- `TestDepFuzzGaps_*` fail when an untrusted-reachable, unfuzzed dependency has
  no exemption fragment, or when an exemption is stale or duplicated; they are
  calibrated on synthetic rows (known-good and planted violations).
- `TestDepFuzzMatrix_GoModAddGoesRed` proves a new direct `require` line is
  parsed, which is the input the gap guard depends on.

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
