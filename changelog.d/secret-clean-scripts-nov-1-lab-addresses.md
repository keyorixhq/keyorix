### Changed

- Docs and scripts no longer carry the lab hosts' addresses (`docs/DAST.md`, `docs/fuzzing/cross-replica-nightly.md`, `scripts/dast/docker-compose.yml`): they use placeholders or `PVE_HOST`.
- `make e2e-smoke-upgrade` now upgrades from v0.97.0 (the previous minor's last patch) instead of v0.96.3.
