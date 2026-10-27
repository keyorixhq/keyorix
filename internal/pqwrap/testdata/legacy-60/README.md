# Frozen legacy-60 key-file fixtures

Each subdirectory holds one `dek.key` (as `wrapped-dek.bin`, because `.gitignore` ignores `*.key`) written by an older Keyorix binary, with
the KEK that wraps it (`kek.hex`) and the DEK it must yield (`dek.hex`).
`TestLegacyKeyFileFixtures_StillLoad` opens every one of them on every test run.
The legacy reader is kept indefinitely (pq-key-wrapping.md §13, Q9).

- `main-94f9d87d2/`: written by `internal/encryption.wrapKey` at origin/main
  `94f9d87d2`, the last commit before key files became keysets. The KEK and DEK
  are SHA-256 of fixed test labels, never real key material.

Never edit or regenerate a fixture. Add a new subdirectory instead.
