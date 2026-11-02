### Testing

- `go test ./internal/statemap` (`TestInvariantDocs_IndexListsEveryFragmentArea`, report-only on pull requests until its first green nightly on main) now flags when a package has an `INVARIANTS.d/` directory but `docs/INVARIANTS.md` has no row linking its `INVARIANTS.md`, so a new invariant area can no longer be left out of the index.
