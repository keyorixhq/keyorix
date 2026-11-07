### Added

- `storage.database.fdatasync` (SQLite only, default `false`): commit with `fdatasync(2)` instead of `fsync(2)`. Ignored with one warning on macOS and Windows. See "Committing with fdatasync" in `docs/CONFIGURATION.md`, including the seccomp caveat. `scripts/powercut` adds a dm-flakey power-cut test for the SQLite backend.

### Changed

- Bumped `modernc.org/sqlite` to v1.62.0.
