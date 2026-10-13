### Changed
- **Access log no longer serialises requests on the global logger lock.** The per-request access line keeps the same fields, format, destination and redaction, but is written through a writer whose lock covers only an in-memory append; lines are still written whole and in order, and overflow past a bounded queue is counted rather than blocking requests.
