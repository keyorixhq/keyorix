### Internal

- The storage test doubles moved out of `internal/core` into the importable test kit `internal/core/storage/storagetest` (ADR-121 decision 2): `HookStore`/`StoreHooks`/`Hooked`, `MockStorage` and the authz stubs. `internal/core`'s tests reach them through one alias file (`storagetest_aliases_test.go`); the seven `core_test` doubles that each embedded the whole `storage.Storage` now use `storagetest.Hooked`, which shrinks the `internal/core_test` build-cache archive. Test code only; no production file changed.
