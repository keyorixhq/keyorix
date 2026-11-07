### Security

- Helm chart (low): the web pod's `/health`, reachable through the public ingress, no longer proxies the server's `/health` body (rate-limit state, uptime, other detail) to unauthenticated callers. It answers a fixed `200 ok` or `503 unavailable` driven by the backend's health (#3910). Probe paths are unchanged: liveness `/nginx-health`, readiness `/health`.
