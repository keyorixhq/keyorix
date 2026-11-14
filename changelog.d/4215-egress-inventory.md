### Documentation
- **Egress inventory.** `docs/security/egress-inventory.md` lists every outbound destination class (trigger, config key, default, field names carried) and answers "does it phone home?" from the code: no call to a Keyorix-operated or third-party endpoint is on by default. Linked from `docs/security/README.md`.

### Testing
- **Egress guard.** `internal/egressguard` fails when a non-test file creates an outbound client (HTTP, TCP/TLS dial, DNS lookup, database, SMTP, cloud SDK) with no row and reason in `docs/security/egress-allowlist.tsv`, when a direct `go.mod` dependency is not classified as client or local, and when shipped code imports a `DEV` tool. Report-only on its first day (`docs/guard-rollout.d/`).
