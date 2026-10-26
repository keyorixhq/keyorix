### Changed

- CI merge-queue test selection: a `_test.go` file under `internal/testutil/` no longer forces the full suite, and rule-3 literals are read with a Go-aware scanner (comments and import paths ignored; rune literals no longer hide real literals).
