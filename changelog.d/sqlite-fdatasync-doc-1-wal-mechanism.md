### Documentation

- `docs/CONFIGURATION.md`, "Committing with fdatasync": says that the server's only WAL truncation is the one-off `wal_checkpoint(TRUNCATE)` in `admin restore`, and tells operators to measure on their own hardware before enabling the option, with the limits of the evidence (ext4 only, dropped-writes fault model only).
