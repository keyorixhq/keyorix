- **INV-STORE-read-path-cache-stamp-before-data** Every read-path cache in this package is
  written ONLY by `cachedRead`/`cachedReadSameRow` (`read_path_cache.go`), which always reads
  the generation stamp BEFORE the data loader, caches only when that stamp read succeeded, and
  treats any stamp-read error or missing row as a MISS — never as "assume unchanged". A
  stamp read after the data would record the pre-change answer under the post-change stamp,
  which is then served until some unrelated write moves that generation again. Why: the same
  defect in both PERF-3 caches (#2767 a revoked permission kept authorizing, #2764 a rotated
  secret kept returning its pre-rotation version). Guard:
  `read_path_cache_guard_test.go:TestReadPathCacheGuard_RealRepo` (no entry write outside the
  helper file; `TestReadPathCacheGuard_Fixtures` calibrates it red and green) plus
  `read_path_cache_race_test.go:TestReadPathCacheRace_WriteInsideTheWindowIsNotCachedStale`
  (a write committed inside each site's generation/data window) and
  `TestReadPathCacheRace_EveryHelperSiteHasARow` (a helper user with no race row fails).
<!-- section: Read-path caches -->
