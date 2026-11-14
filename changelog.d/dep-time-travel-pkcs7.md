### Testing
- **Dependency time-travel differential harness (`scripts/fuzzing/time-travel/`).**
  Builds one driver per historical version of a pinned library — each in its own
  throwaway module, offline from the module cache, never touching the repo's
  `go.mod`/`go.sum` — runs them all on a shared corpus, and diffs the canonical
  verdict/error-class/parsed-shape/bounded-work per input between consecutive
  versions. Instantiated for `github.com/digitorus/pkcs7` across its three
  pinned versions; the differential independently re-derives the
  GHSA-3xqc-rpq8-wgp9 BER nesting-depth amplification fix (old transcodes work
  proportional to nesting depth, new caps descent at 500) and confirms the
  2026-09 → 2026-11 bump changes nothing on the `pkcs7.Parse` surface Keyorix
  reaches. Adds `FuzzPKCS7TimeTravelOracle`
  (`internal/libconformance`): coverage-guided fuzzing of the repo-pinned
  (new) `pkcs7.Parse` with an older version as a subprocess oracle, failing only
  when the new version accepts what the old rejected or panics.
