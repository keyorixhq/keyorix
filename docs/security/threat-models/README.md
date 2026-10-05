# Per-Component Threat Models

Each document here narrows [`../threat-model.md`](../threat-model.md) (the
system-wide threat model — trust boundaries, STRIDE, residual risks) to
one component, with a dedicated data-flow diagram and more operational
detail. None of these contradict the system-wide document; where a
narrower document and the system-wide one might seem to disagree, the
system-wide document is the longer-standing, more-reviewed source —
that's a bug in the narrower document, not a real disagreement, and
should be filed as an issue.

| Component | Covers |
|---|---|
| [`server-api.md`](server-api.md) | REST + gRPC request path, the `core.Authorize` chokepoint as seen from the transport layer |
| [`authentication.md`](authentication.md) | Sessions, PAT, machine identity, OIDC, SAML SSO, TOTP MFA, WebAuthn, emergency admin recovery |
| [`authorization-rbac.md`](authorization-rbac.md) | Scoped RBAC, the admin-bypass structural marker, privilege-ceiling derivation |
| [`audit-chain.md`](audit-chain.md) | Hash-chained audit events, signed checkpoints, offline verification |
| [`secret-storage-key-hierarchy.md`](secret-storage-key-hierarchy.md) | Envelope encryption, the KEK/DEK hierarchy, Shamir, HSM/KMS/TPM providers |
| [`backup-restore.md`](backup-restore.md) | `admin backup`/`restore` (SQLite), the operator-driven Postgres path, audit-chain-verified restore |
| [`update-bundles-airgap.md`](update-bundles-airgap.md) | Signed offline update bundles, offline license validation, air-gapped OIDC |
| [`connectors.md`](connectors.md) | AWS/Azure/GCP/Vault/rotation-target connectors, tenant scoping, SSRF guards |
| [`kubernetes-operator.md`](kubernetes-operator.md) | The `KeyorixSecret` CRD controller, namespace-scoped RBAC, confused-deputy guard |
| [`web-ui.md`](web-ui.md) | Session-cookie delivery, CSRF, CSP, client-side state — with the same narrower-scope caveat the system-wide document states |

## What's not here

The sync agent and External Secrets Operator integration share the
`kubernetes-operator.md` document's underlying API-read path (same
scoping, same "never log values" property) and don't have their own
dedicated file — see that document's own introduction for the pointer
to [`../../k8s-sync.md`](../../k8s-sync.md) and
[`../../k8s-eso.md`](../../k8s-eso.md) if those specific delivery modes
need their own deeper pass later.

## GAPs filed while writing these

Two genuinely open items surfaced while grounding these documents in
the real code rather than being invented for this pass — both labeled
`threat-model-gap`:

- [#2733](https://github.com/keyorixhq/keyorix/issues/2733) — `SearchAuditLogs`/`AccessHistory` leak `IPAddress` (PII) where a sibling route already redacts it (server-api.md)
- [#2734](https://github.com/keyorixhq/keyorix/issues/2734) — no process-level isolation for connector code (connectors.md)
