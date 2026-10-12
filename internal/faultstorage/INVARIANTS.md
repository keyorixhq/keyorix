# internal/faultstorage invariants

Read this before changing anything in `internal/faultstorage` — the test-only
fault-injection wrapper around `storage.Storage` and its generator (`./gen`).

Format: `INV-FAULTSTORAGE-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

- **INV-FAULTSTORAGE-01** `FaultyStorage` implements every `storage.Storage` method
  explicitly and does not embed `storage.Storage`, so a new interface method without a
  wrapper is a build failure, never a silently un-faultable method. Why: package doc in
  `faultstorage.go`; `gen/main.go` doc. Guard: `var _ storage.Storage = (*FaultyStorage)(nil)`
  in `faultstorage.go` (go build).
- **INV-FAULTSTORAGE-02** The committed `faulty_storage_generated.go` is byte-for-byte the
  output of `./gen` over the current interface source — no hand edits, no hand-merged
  conflict resolutions (on a conflict: take main's version, then `go generate
  ./internal/faultstorage/`; see `README.md`). Covers the compiling-but-stale cases the
  build cannot: a hand-edited wrapper body, reordered methods, changed parameter names.
  Guard: `generated_fresh_test.go` (`TestFaultyStorageGenerated_IsFresh`).
- **INV-FAULTSTORAGE-03** The generator's output is deterministic for a given interface
  source and toolchain (sorted file, method and import order; no map iteration while
  emitting), so INV-FAULTSTORAGE-02 reports real drift rather than flaking. Guard:
  `gen/main_test.go` (`TestGenerate_IsDeterministic`). Does not cover cross-toolchain
  `go/format` differences.
