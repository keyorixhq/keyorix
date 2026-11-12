### Added

- A repository guard (`TestNoDirectEnvReadOfFileCapableVars`) fails when non-test code outside `internal/config` and `internal/secretenv` reads a secret that has a `*_FILE` form directly with `os.Getenv`/`os.LookupEnv`/`syscall.Getenv`, and tests pin that a bootstrap-token or Vault-token file wider than `0600` is refused at boot (#3830). No such read exists today; `KEYORIX_TOKEN_FILE` is already honoured by `keyorix-mcp` and `keyorix-k8s-sync`.
