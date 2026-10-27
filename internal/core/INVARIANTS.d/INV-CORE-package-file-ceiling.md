- **INV-CORE-package-file-ceiling** `internal/core` holds at most 260 non-test `.go` files, and no
  package under `internal/` or `server/` exceeds 260 files or 44 transitive dependents in the module.
  Today `internal/core` has 226 files (68,522 lines), the largest package by far, so it is the one
  this ceiling is closest to (87%); the next are `server/http/handlers` 130 and `internal/storage/store`
  96. A change that would add the file that crosses the ceiling splits instead: put the new code in a
  sub-package or a leaf with a narrow interface (like `internal/core/ports` and `internal/core/rules`), or raise the ceiling in `scripts/ci/check-growth-guards.sh` in the same PR
  with the reason added to `docs/design/architecture-growth-baseline.md`. Do not add a new shared
  append-only file: add per-item fragments and a build/reduce step, as `changelog.d` and
  `docs/security-closures.d` do.
  Why: nobody asks what a design costs in CI time and review at design time (the architecture-cost
  lesson behind this: AI does not feel the pain); the build has to. Numbers and method:
  `docs/design/architecture-growth-baseline.md`; rule: `docs/ARCHITECTURE.md`, "Growth ceilings".
  Guard: `scripts/ci/check-growth-guards.sh` (`make check-growth`; `--self-test` is red one below the
  real maximum and green at it), plus the warn-only `scripts/ci/check-no-new-ledger.sh`. Not covered:
  CI does not run it until the `ci.yml` line in the PR that added it is applied; a single global
  ceiling does not stop `server/http/handlers` or `internal/storage/store` growing to it.
