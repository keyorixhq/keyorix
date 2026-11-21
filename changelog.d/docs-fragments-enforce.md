### Documentation

- A feature or fix PR now documents a new config key in `docs/configuration.d/` and its upgrade note in `docs/upgrading.d/` and never edits `docs/CONFIGURATION.md` or `docs/UPGRADING.md` (rule added to `CLAUDE.md`). Dedicated `docs/fold-*` / `docs/consolidate-*` PRs fold the fragments into the flat files with the new `scripts/docs/fold-fragments.sh` (`--dry-run`, `--check`).
