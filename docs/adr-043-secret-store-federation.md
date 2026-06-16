# ADR-043: Secret-store federation (Keyorix Connect)

## Status

Accepted — first slice shipped (AWS Secrets Manager read-through). GCP Secret
Manager, HashiCorp Vault, and caching are planned follow-ups.

## Context

Teams adopting Keyorix often already hold secrets in an external store (AWS Secrets
Manager, GCP Secret Manager, HashiCorp Vault). Migrating everything up front is a
hard sell. They want to reach those existing secrets *through* Keyorix — with
Keyorix's RBAC, audit trail, and a single API — without moving them.

## Decision

Add **Keyorix Connect**: a **read-through** federation layer.

- A `Connector` (`internal/connect`) fetches the **current value** of a secret held
  in an external store on demand. It is **read-only** — no create/update/delete:
  federation proxies reads, it does not own the secret.
- Keyorix **never imports or persists** the federated value. A read is proxied,
  returned to the authorized caller, and **audited** (`connect.secret_read`); nothing
  is stored. (This keeps the source of truth in the external store and avoids a
  stale-copy / dual-write problem.)
- Each backend's SDK is contained behind an **interface seam** (e.g. `smGetAPI`), so
  the engine is unit-tested with a fake and the SDK dependency stays isolated —
  mirroring the dynamic-secrets cloud backends (ADR-035).
- Backend credentials come from the backend's **ambient identity chain** (e.g. the
  AWS standard chain: env / instance-profile / IRSA), never from Keyorix config.
- **Opt-in, disabled by default** (`connect.enabled`). The capability is independent
  of how it is licensed/packaged (a commercial-tier gate can be layered later without
  changing the model).

### API

- `GET /api/v1/connect/connectors` — list configured connector names.
- `GET /api/v1/connect/{name}/secret?ref=<id>` — read-through a secret. `ref` is
  connector-specific (for AWS Secrets Manager: the secret name or ARN).

Both are gated by `secrets.read` (a federated read is a secret read) and audited.

## Alternatives considered

- **Import/sync** (copy external secrets into Keyorix): rejected for the first slice —
  it creates a stale-copy / dual-write problem and a larger blast radius. Read-through
  keeps the external store authoritative. Sync can be added later as an explicit,
  separate mode.
- **Per-connector credentials in config**: rejected — ambient identity (IRSA/instance
  profile) is the established pattern in this codebase (KMS, STS, S3) and avoids
  storing cloud credentials.

## Consequences

- A federated read depends on the external store's availability and latency (a
  backend failure surfaces as `502 Bad Gateway`). Caching (with a TTL) is a planned
  follow-up to bound this.
- Authorization is coarse for now (`secrets.read` globally). A federated read is
  bounded by the backend identity's IAM policy (the load-bearing control) plus an
  optional per-connector `allowed_refs` prefix allowlist enforced in Keyorix before
  the backend call. Finer per-reference RBAC and a dedicated `connect.read`
  permission (so native read access doesn't imply external-store read) are follow-ups.
