# operator/internal/controller invariants

Read this before changing the KeyorixSecret reconciler. It holds cluster-wide Secret
RBAC and acts on behalf of namespace-scoped tenants who may only create a `KeyorixSecret`
custom resource, so the rules below are what keep it from becoming a confused deputy:
shipping a Secret's bytes to an attacker-chosen server, writing/deleting a Secret it does
not own, or leaking a fetched value into a widely-readable subresource.

Format: `INV-KOP-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-KOP-<slug>.md`, one per file.
