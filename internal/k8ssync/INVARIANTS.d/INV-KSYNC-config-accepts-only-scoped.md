- **INV-KSYNC-config-accepts-only-scoped** A config that `validate()` accepts always
  satisfies the invariants the rest of the agent then trusts blindly: `keyorix_url`
  passes the cleartext gate ([[INV-KSYNC-token-url-tls-only]]), `project_id != 0` (every
  secret lookup is scoped to exactly one project server-side — #Bug1), and every mapping
  has a non-empty `ref` and a valid `(namespace, name, key)` Kubernetes target triple
  (RFC1123 label / subdomain, K8SSYNC-001/002). Without any one of these the agent would
  send a token in cleartext, resolve a same-named secret from the wrong project, or write
  to an ill-defined target. Why: `Config.validate` / `validateMapping` (`config.go`,
  `sync.go`). Guard: `FuzzConfigValidate` (`internal/k8ssync`) re-checks each property
  independently over fuzzed YAML.
