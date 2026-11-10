### Documentation

- "Committing with fdatasync" in `docs/CONFIGURATION.md` now explains why the option helps (after a complete checkpoint SQLite overwrites the WAL in place, and only a commit that grows the file pays for the size update, which `fdatasync` does not skip), warns that `journal_size_limit` or truncating the WAL after checkpoints makes commits extend the file again and removes most of the gain, and tells tests that want fail-fast behaviour to give `BeginTx` a context with a short deadline. A DSN test pins that `journal_size_limit` is not set by default and that an operator-supplied value passes through untouched.

### Internal

- Posture: a test now derives every deprecated setting alias from the alias table and checks that a config file writing only the old name is labelled explicit, not shipped-default (#2925). The SSO-only-administrator warning (#2914) gained a two-local-admins test.
