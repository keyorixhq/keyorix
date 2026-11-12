### Changed
- **`admin init` names the database backend it set up (#3523).** For SQLite it prints `Database: SQLite (storage.type "sqlite"), file <path> created|already present`; a PostgreSQL config still creates no SQLite file and says so.

### Documentation
- **Upgrade note for the config keys the next minor release rejects (#3743).** `secrets.chunking`, `secrets.limits.max_secrets_per_user` and `server.http.keepalive` are ignored today and each logs a deprecation warning; the note says how to remove them and that `audit verify` reads `NOT PROVEN` until the first full re-walk (`audit verify --full`). A test now fails when a key in the ignored list is not named in an upgrade note.
