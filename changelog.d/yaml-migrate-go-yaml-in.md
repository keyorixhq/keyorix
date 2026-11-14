### Changed
- **YAML parsing moves to the maintained `go.yaml.in/yaml/v3`.** `gopkg.in/yaml.v3` was
  archived upstream in April 2025 and receives no fixes. Keyorix, `keyorix-cli` and
  `keyorix-migrate` now import `go.yaml.in/yaml/v3` v3.0.6 (the YAML organization's fork, same
  API). Behaviour is unchanged: the decoder and the duplicate-key and unknown-key checks are the
  same code. The `internal/core` closure guard now forbids both import paths.
