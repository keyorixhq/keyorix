### Fixed

- `admin diagnose` is read-only: with missing key files it reports each missing absolute path and creates nothing (no salt, DEK or `dek.lock`). It also reports a DEK or salt that is missing from an otherwise present key set instead of generating it.
- With a relative `storage.encryption.dek_path` / `salt_path` the server logs one startup warning naming the resolved absolute key paths and the `dek.lock` path (relative key paths resolve against the working directory, not the config directory; where keys are read from is unchanged). The "another process already holds the DEK lock" refusal now names the lock file (`... at /abs/path/dek.lock`).
