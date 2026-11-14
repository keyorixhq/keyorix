### Fixed
- **`admin verify-audit` explains a tampered row in plain words.** The reason for a row whose recorded
  hash no longer matches its contents now reads "the recorded entry_hash does not match the row's
  contents — the row was changed after it was written" instead of naming internal encodings. Text
  only: the result fields, exit codes, JSON keys and the hash chain are unchanged. The same wording
  is used by the chain-encoding migration when it refuses to re-hash a modified row.
- **`keyorix secret versions` no longer prints an internal note** about size/algorithm columns.
- **A wrong bootstrap token on `keyorix system init` gets its own hint:** check that
  `KEYORIX_BOOTSTRAP_TOKEN` / `KEYORIX_BOOTSTRAP_TOKEN_FILE` matches the token the server was started
  with, instead of "ask a project admin, or request access". The exit code is unchanged.
- **`scripts/demo/scenario-k8s-sync.sh` is SKIPPED (exit 2), not FAILED,** when `KEYORIX_SERVER`,
  `KEYORIX_TOKEN` or `KX_SECRET_ID` is not set, so `scripts/demo/catalogue-check.sh` no longer reports
  a failure for a scenario it cannot supply.
