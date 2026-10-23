### Security

- With `storage.encryption.key_dir_lock: database`, a replica whose key-initialisation lock ends while it generates or recovers the key files (backend terminated, PostgreSQL failover, pooler timeout) now refuses to start instead of serving: a sibling replica may have generated its own keys at the same time.
- An admin command run with `--force` without the exclusive database lock now says so in its audit event (it was printed to the terminal only).
- `keyorix-server admin recover-admin` with a wrong recovery key now writes an `admin.recover_admin_failed` audit event (the host user, the target account and the key generation; never the key).
- On SQLite, a server and an admin command now exclude each other when one names the database as a `file:` URI (`file:/data/secrets.db`, `file:///...`, percent-encoded) and the other as a plain path, and a database in a directory whose name contains `mode=memory` is guarded too.
