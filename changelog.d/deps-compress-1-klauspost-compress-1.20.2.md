### Security
- **`github.com/klauspost/compress` bumped to v1.20.2.** Clears GO-2026-6865 (fixed in
  v1.20.2), flagged by `govulncheck` as reachable. No code changes; `go build`, `go vet` and
  the affected packages' tests pass unchanged.
