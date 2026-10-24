# ADR-116: Splitting `internal/core`: tests first, the kernel stays, leaves only where they pay

**Status:** Proposed (CORE-SPLIT-DESIGN-1, 2026-10-20). Needs Andrei's acceptance.
**Related:** ADR-109 (core depends on interfaces), ADR-112 (secure-by-default baseline: unchanged by this ADR),
CORE-DECOUPLE plan (third-party libraries), WIRING-SPLIT-1 (shared wiring files).
**Evidence:** the measurement report `reports/SESSION-CORE-SPLIT-DESIGN-1.md` (Keyorix planning notes).
Numbers are kept out of this ADR on purpose; each implementing PR pastes its own before/after.

## Context

`internal/core` is one Go package holding most of the product's business logic and most of its tests.
Every edit to any of its files rebuilds one large test archive and reruns the whole core test suite, and every
source edit invalidates the test binaries of every package that imports core. Go recompiles only a changed
package and its direct importers when the output is unchanged, so compile time is not the problem; test
reruns, test-archive size and merge conflicts on a few shared files are.

A file- and symbol-level dependency analysis shows:
- a strongly connected kernel (identity, authentication, secrets, sharing, role management, audit, authorization)
  that cannot be separated without interfaces running in both directions through security decisions;
- a ring of near-leaf features (reports, reminders, compliance, rotation, anomaly detection, dynamic secrets) that
  depend on the kernel through a small, repeated seam (storage, clock, audit writes, notifications);
- a large set of tests that use only core's exported API;
- a few pure value types (OIDC verification, PAT restrictions, anomaly algorithms) that use no core state;
- two shared files (`internal/core/storage/interface.go`, `internal/storage/factory.go`) where most schema and
  storage features collide.

## Decision

1. **The kernel is not split.** No session moves kernel files into other packages. Changes to the kernel's shape
   need their own ADR.
2. **Tests move before code.** Tests that use only exported API move to one test-only package,
   `internal/core/coretests`. Shared storage doubles move to `internal/core/storage/storagetest`, a non-test package
   that only `_test.go` files may import. Fuzz targets, Postgres-gated tests, registry entries and any test named by
   a ledger row stay in `internal/core`.
3. **Production code leaves core only as pure leaves:** packages with no `*KeyorixCore` and no import of
   `internal/core`, imported by core, with type/var aliases in core so callers do not change.
   Sibling services behind ports (the ADR-109 shape) are allowed later, only after a pilot, and only through a
   narrow kernel port that core implements and `server/main.go` wires.
4. **Shared files are split by domain within their package:** the storage interface into embedded per-domain
   interfaces (generators follow embedded interfaces), the migration function into ordered per-domain steps.
5. **Handlers** may move into per-domain subpackages with a shared `httpx` helper package, a few groups at a time,
   each measured, because every new test package that links core costs a link on every core change.

## Rules (machine-checked)

The checks and where they live are listed in `internal/core/INVARIANTS.d/INV-CORE-package-boundaries.md`.

- R1: no extracted package imports `internal/core` (go list). Extracted packages are registered in the core family
  (`internal/testutil/srcpath`, one `corefamily_<leaf>.go` file per package).
- R2: core's production closure of keyorix packages equals an exact allowlist; leaf internals live under
  `<leaf>/internal/` so the compiler refuses core importing them.
- R3: no production file imports `storagetest` or `coretests`.
- R4: every non-test file in `internal/core` belongs to exactly one cluster (`internal/core/CLUSTERS.d/`).
- R5: every source-scanning guard that walks core walks the whole core family (`srcpath.CoreFamilyDirs`), and a
  coverage test proves no family file is skipped.
- R6: every file name a guard names by literal exists.
- Import cycles are refused by the compiler.

## Process

One extraction per PR, mechanical only (move, qualifier rewrite, aliases), CORE lane only, opened in a quiet window
after every open PR touching the moved files has merged. Each PR carries the move script, a `provemove` proof
(`scripts/refactor/provemove`: normalised declarations equal before/after), equal test-name sets, an unchanged
exported API or production dependency closure as applicable, and green guards. Conflicts are resolved by re-running
the move script on fresh main. Rollback is a revert PR proven the same way.

## Consequences

- Edits to moved tests rebuild and rerun only their own package; core's test archive shrinks.
- Three security fuzz targets run outside core's coverage map.
- Schema and storage features edit per-domain files instead of one shared function and one shared interface.
- Every new package adds a test binary that links core; the number of such packages is kept small on purpose.
- Guards that walk core become explicit about which directories they cover.

## Alternatives considered

- **Split the kernel by feature (big bang):** rejected; the dependency graph is cyclic through security decisions.
- **Extract features and let core import them to delegate:** rejected; it keeps the rebuild and rerun cost identical.
- **One test package per feature:** rejected; each adds a large link per core change.
- **Build tags to drop features:** rejected; they are security features (ADR-109's own decision).

## Not decided here

Whether to introduce the kernel port and sibling services (needs the pilot's result); a gorm-free models package
(ask core-decouple-gorm-models-split).
