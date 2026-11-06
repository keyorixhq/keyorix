### Documentation

- `changelog.d/migrate-vault-tails-1.md`: the `--path-map` examples use numeric project and environment IDs, as `keyorix-migrate` requires. `docs/releases/v0.97.0-draft.md`: the roles row says "added in schema epoch 7", and the rebase note names the current schema epoch (9).
- `scripts/check-doc-links.py --refs` resolves a backticked path against the referencing file's own directory as well as the repo root (no more false positives on `operator/...` links in `docs/`); `--self-test` checks it. The `POST /api/v1/audit/checkpoint` handler comment now says the checkpoint key is KEK-derived, so a DEK rotation does not need a re-baseline.
