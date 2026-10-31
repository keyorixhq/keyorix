### Changed

- `go test ./internal/statemap` (`TestInvariantDocs_RealRepo`) now fails when a package has an `INVARIANTS.d/` directory but `docs/INVARIANTS.md` has no row linking its `INVARIANTS.md`, so a new invariant area can no longer be left out of the index.
