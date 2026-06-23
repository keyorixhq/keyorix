# ADR-058: Kubernetes dynamic-secret backend

## Status

Accepted.

## Context

Keyorix's dynamic-secrets engine (ADR-035) mints short-lived credentials on demand and
leases them with an enforced TTL. Alongside the database backends (PostgreSQL, MySQL,
MongoDB, Redis) it already has cloud-IAM backends that hand back self-expiring tokens
rather than database users: AWS STS, GCP, and Azure. Kubernetes is the obvious next
target — workloads frequently need a short-lived **ServiceAccount token** (to call the
API server or an in-cluster service that trusts SA tokens) without embedding a
long-lived token in a Secret.

The provider framework is fully generic: `backend_type` is a free-form string through
storage, HTTP, and gRPC, and the engine is resolved by a single factory switch. Adding a
backend is therefore an engine plus its registration — no schema, proto, or transport
changes.

## Decision

Add a `kubernetes` dynamic-secret backend that mints a ServiceAccount token via the
Kubernetes **TokenRequest** API (`POST …/serviceaccounts/{sa}/token`).

- **Ephemeral, like the cloud backends.** The API server enforces the token's
  `expirationTimestamp`, so `SupportsNativeExpiry` and `IsEphemeralBackend` are both
  true; `Revoke` is a no-op and `Renew` is refused (issue a fresh lease). The lease TTL
  is floored at the Kubernetes 10-minute minimum so the lease's stated TTL matches what
  the API server actually mints.
- **JSON "admin DSN".** The encrypted config carries
  `{"namespace","service_account","audiences"?}`. When `api_server`/`ca_cert`/`token`
  are omitted the engine uses the standard **in-cluster** configuration (the mounted
  service-account token and CA) — so no credentials live in Keyorix config when the
  server runs in the cluster. The calling identity must hold `create` on the
  `serviceaccounts/token` subresource for the target ServiceAccount.
- **Dependency-free.** The TokenRequest is a small REST call over `net/http` with the
  cluster CA pinned, mirroring the Kubernetes sync agent's REST sink — no `client-go`.
- **Credential shape.** The issued credential carries `token`, `namespace`,
  `service_account`, and `expiration` in `Fields` (no username/password), exactly like
  the AWS STS / GCP backends.

### Safety properties

- **Fail-closed TLS.** An explicitly-configured `api_server` requires a `ca_cert`; the
  engine never skips verification (an unverified API server could return any token).
- **Path-segment guard.** The namespace and service-account name are validated (DNS-label
  charset) before being placed into the request path, rejecting traversal/injection
  rather than escaping.

## Alternatives considered

- **client-go / TokenRequest via the SDK.** Rejected: pulls a heavy dependency for one
  REST call; the existing REST-sink pattern already proves the net/http approach.
- **Long-lived SA token Secrets.** Rejected: that is exactly the static-secret sprawl
  dynamic secrets exist to remove.
- **A separate "k8s token" feature outside the dynamic engine.** Rejected: leasing, TTL
  enforcement, audit, and CLI/HTTP/gRPC surface already exist in the dynamic engine;
  reusing it is strictly less code and a consistent operator experience.

## Consequences

- Operators can register a `kubernetes` dynamic-secret config and issue short-lived SA
  tokens through the same CLI/API/gRPC as every other backend.
- The Keyorix server (or its ambient identity) needs RBAC to create tokens for the target
  ServiceAccounts — an operator concern, documented in the CLI help.
