### Documentation
- **Air-gap runbook walked end to end on SQLite.** `docs/AIRGAP_RUNBOOK.md` now says that the generated config has no `audit_checkpoints:` block, that anchored `admin verify-audit` needs the server stopped (or `--db <copy>`), and that only the `auto_cert` refusal is listed in `startup-refusals.md`.

### Testing
- **New guard `TestScriptsDeprecatedCLIFlags_*` (internal/statemap):** fails when a script under `scripts/` calls a CLI flag the built CLI deprecates on that command (seeded with `--format` and `--by`; `secret export --format` stays allowed).
