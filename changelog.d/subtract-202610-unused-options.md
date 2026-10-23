### Deprecated
- **`secrets.chunking.*` and `secrets.limits.max_secrets_per_user` are deprecated.** No code ever read them: there is no secret chunking and no per-user secret cap. A config that still sets them loads as before but logs a start-up warning; they will be rejected after the next minor release.
- **`keyorix user create --by` is deprecated.** It never had an effect, because the acting admin is always the session behind your token. Passing it now prints a warning, and it will be removed in the next minor release.

### Documentation
- **The keys above are gone from the shipped config template, the sample configs and CONFIGURATION.md.** That section now documents the real `secrets.limits.max_secret_size`.
