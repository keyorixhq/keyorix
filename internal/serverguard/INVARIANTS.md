# internal/serverguard invariants

Read this before changing anything in `internal/serverguard`: the reader/writer guard that keeps
`keyorix-server admin` commands and live servers off the same database at the same time
(`serverguard.go`: a flock on the SQLite `<database>.server.lock` sidecar, a PostgreSQL advisory
lock), and the key-initialisation lock (`keyinit.go`). The package doc comment lists what the
guard does not cover. How each lock behaves when it is lost: `internal/storage`
INV-STORAGE-session-advisory-lock-loss and [docs/design/pooler-lock-loss.md](../../docs/design/pooler-lock-loss.md).

Format: `INV-SERVERGUARD-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

Every invariant is a slug-ID fragment in [INVARIANTS.d/](INVARIANTS.d/), one per file.

## SQLite sidecar

The SQLite lock lives on the sidecar's inode, not its name. Both sides check that the name
still points at the file they hold, at acquisition and every watch interval while they hold it.

## Lock loss

A holder whose lock is found lost stops rather than runs on beside the process the lock was
keeping out.
