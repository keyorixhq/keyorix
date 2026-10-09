# internal/faultstorage

Test-only fault-injection wrapper around `storage.Storage` — see the package doc in
`faultstorage.go` for what it is for. Invariants: [INVARIANTS.md](INVARIANTS.md).

## The generated file

`faulty_storage_generated.go` is produced by `./gen` from the `storage.Storage` interface
source (`internal/core/storage/interface.go`). Never edit it by hand. Regenerate after any
change to that interface:

```sh
go generate ./internal/faultstorage/
```

(`go generate` runs the generator from this directory; the generator finds the module root
via `go.mod`, so `go run ./internal/faultstorage/gen` from the repo root works too.)

`TestFaultyStorageGenerated_IsFresh` (`generated_fresh_test.go`) fails in plain `go test`
whenever the committed file is not byte-for-byte what the generator produces now.

## On a merge conflict in `faulty_storage_generated.go`

Do not resolve the conflict hunks by hand. Two PRs that each add storage methods both
regenerate this file, so it conflicts often; a hand-merged result can compile and still be
wrong (methods out of order, a hunk from the wrong side). Instead:

```sh
git checkout origin/main -- internal/faultstorage/faulty_storage_generated.go   # take main's version
go generate ./internal/faultstorage/                                             # regenerate from the merged interface
go test ./internal/faultstorage/                                                 # freshness test must pass
```

The merged `interface.go` is the source of truth; the generated file is derived from it.
