### Added

- `storage.database.fdatasync` (SQLite only, default `false`): commit with `fdatasync(2)` instead of `fsync(2)`. On Linux ext4 a single-writer audit commit dropped from about 4 ms to 2.3 ms p50. Ignored with one warning on macOS and Windows. See "Committing with fdatasync" in `docs/CONFIGURATION.md`, including the seccomp caveat and the dm-flakey power-cut results (`scripts/powercut`).

### Changed

- Bumped `modernc.org/sqlite` to v1.62.0.
