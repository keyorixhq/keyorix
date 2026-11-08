### Testing

- Add an upgrade-path fuzzer (`TestUpgradePathFuzz`, opt-in via `KX_UPGRADE_BINDIR`) that installs and populates released tags, then upgrades with the current tree through a clean migrate, a repeated migrate, SIGKILLed migrates and the old release's own backup. It found that backups taken by v0.95.2 and v0.95.3 with soft-deleted secrets cannot be restored (fixed from v0.96.0); see `server/UPGRADE_PATH_FUZZ.md`.
