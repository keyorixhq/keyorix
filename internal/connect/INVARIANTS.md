# internal/connect invariants

Read this before changing anything in `internal/connect`. This package is the
read-through Connect layer: each cloud backend (Vault, AWS Secrets Manager, Azure
Key Vault, GCP Secret Manager) resolves a reference to a secret value over an
outbound HTTP/gRPC client that runs under the ambient cloud identity. The shared
outbound-hardening pieces live in `hardened_client.go` — a link-local-refusing
dialer, a post-decompression response-size cap, redirect refusal, and (for the
Azure SDK path) an error-body scrub — and every backend's response flows through
them before the SDK or the connector parses it.

Format: `INV-CONNECT-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-CONNECT-<slug>.md`, one per file.
