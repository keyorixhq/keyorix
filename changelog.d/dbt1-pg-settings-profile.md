### Added
- **Helm: `postgresql.settings` for the bundled PostgreSQL.** Extra server settings, rendered as `postgres -c key=value` alongside the secure-baseline TLS args. Empty by default (rendered output unchanged). The chart refuses `synchronous_commit`, `fsync` or `full_page_writes` set to off. Guarded by `TestHelmPostgresSettings`.

### Documentation
- **docs/PERFORMANCE.md: a production PostgreSQL profile** (memory, WAL compression, checkpoint spacing; durability left on), with what it measurably changes (WAL volume) and what it does not (read throughput, `commit_delay`). The SQLite advice now says the server's own settings are complete: the cache/mmap/temp_store PRAGMAs it used to recommend made no measurable difference.
