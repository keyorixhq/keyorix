### Fixed
- **`admin encryption init` names the key directory when it cannot open `dek.lock` for permissions (#3742).** A missing key directory and real lock contention already had their own messages; an unreadable or unwritable key directory printed a bare `open DEK lock file: permission denied`. It now names the directory and says to fix its owner or mode (0700), and never suggests a live server.

### Testing
- **End-to-end proof that `admin init` leaves SQLite alone for PostgreSQL (#3523).** With `--storage-type postgres`, or a supplied config with `storage.type: postgres`, init in an empty directory creates no `.db`, `-shm`, `-wal` or lock file; the SQLite default still creates `keyorix.db`.
