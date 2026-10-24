- **INV-CORE-package-boundaries** The package boundaries of the `internal/core` split (ADR-116)
  hold, and no source-scanning guard over core goes blind when a file moves:
  (R1) no package extracted from core (the core family, registered one
  `internal/testutil/srcpath/corefamily.d/<leaf>.tsv` row per package) imports `internal/core`;
  (R2) the keyorix packages in core's production closure are exactly the reviewed list, and none of
  the test-only packages (`srcpath.CoreTestOnlyDirs`: `internal/core/coretests`,
  `internal/core/storage/storagetest`) is among them;
  (R3) no production `.go` file anywhere in the repository imports a test-only package;
  (R4) every non-test `.go` file directly in `internal/core` belongs to exactly one cluster of
  `internal/core/CLUSTERS.d/` (kernel by exact name, the other clusters by glob);
  (R5) every guard in `internal/core` and `internal/core/guards` that scans core's sources lists them
  through `srcpath.CoreFamilyGoFiles` (internal/core plus every registered extracted package), never
  by listing a directory itself.
  Why: CORE-SPLIT-DESIGN-1 found 11 guard files walking `internal/core` with a non-recursive
  `ReadDir`/`Glob`, which would have silently stopped seeing any moved file, and no check that an
  extracted leaf stays below core.
  Guard: R1 and R2 `internal/core/ports/core_family_deps_test.go` (`TestCoreFamilyNeverImportsCore`,
  `TestCoreKeyorixDepsMatchAllowlist`, `TestCoreFamilyDeps_SelfTest`); R3
  `internal/core/guards/test_only_packages_guard_test.go`; R4
  `internal/core/guards/core_clusters_guard_test.go` (`TestEveryCoreFileHasOneCluster`, also red on a
  stale pattern); R5 `internal/core/guards/core_family_walkers_test.go` (`TestNoAdHocCoreDirListing`:
  every directory-listing call in those test files is converted or allowlisted with a reason;
  `TestCoreWalkersSeeEveryCoreFamilyFile`) and `internal/testutil/srcpath/corefamily_test.go`. R6, the
  companion check that a file a guard names by literal still exists, is
  `internal/core/guards/named_source_files_guard_test.go`.
  Not covered: recursive `filepath.WalkDir` guards rooted at `internal/core` (they see subpackages of
  core but not a leaf extracted to `internal/<leaf>`: the first such extraction re-points them), guards
  outside `internal/core` and `internal/core/guards`, test-only imports of core by a family package,
  and build-tagged variants other than the default tags.
