# internal/k8ssync invariants

Read this before changing the Keyorix Kubernetes sync agent (the in-tree sidecar variant
of the operator). It loads a YAML config and sends the machine-identity token
(`KEYORIX_TOKEN`) as a bearer header to the configured server on every request, then
materialises referenced values into Kubernetes Secrets. The rules below are what keep the
token on TLS and keep every lookup and target scoped.

Format: `INV-KSYNC-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-KSYNC-<slug>.md`, one per file.
