### Added
- **ADR-124 (Proposed): per-user UI settings live on the server, in SQL.** Theme, language, timezone, sidebar state and page-hint state follow the user across browsers; the browser keeps only a cache for first paint. Design only; no code and no behaviour change. ADR-123 now stores hint state this way.
