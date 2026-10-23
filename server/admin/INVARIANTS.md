# server/admin invariants

Read this before changing anything in `server/admin` (the `keyorix-server admin ...`
commands: backup, restore, migrate, key and recovery operations). Each rule names the test
that fails when it stops being true.

Format: `INV-ADMIN-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

Invariants are kept one per file in `INVARIANTS.d/` (see `docs/invariants-fragments.md`).

## Backup and restore
