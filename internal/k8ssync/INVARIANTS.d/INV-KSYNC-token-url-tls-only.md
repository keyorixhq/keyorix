- **INV-KSYNC-token-url-tls-only** `keyorix_url` is accepted only when its scheme is
  `https`, or `http` with the literal hostname `localhost` — never `http` to a loopback
  IP or any other host (K8SSYNC-007). The agent sends `KEYORIX_TOKEN` as a bearer header
  on every request, so a cleartext non-localhost URL would expose a secrets-read-capable
  token on the cluster network; loopback IPs are excluded because DNS an attacker
  controls could map one to a routable address. Why: `validateKeyorixURL`
  (`config.go`), K8SSYNC-007. Guard: `FuzzValidateKeyorixURL` (`internal/k8ssync`)
  computes the accept condition independently of the validator's control flow.
