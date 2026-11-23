### Testing
- Classified `github.com/boombuler/barcode`, `github.com/google/uuid` and
  `github.com/klauspost/compress` in the egress inventory's `dependencyKinds` as
  local (no connection of their own; only test files import them) and moved their
  `go.mod` lines out of the `// indirect` block, as `go mod tidy` does. This stops
  `TestEgressEveryDirectDependencyIsClassified` failing on every Dependabot PR that
  touches `go.mod`.
