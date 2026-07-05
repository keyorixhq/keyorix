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
  true; `Renew` is refused (issue a fresh lease). The lease TTL is floored at the
  Kubernetes 10-minute minimum so the lease's stated TTL matches what the API server
  actually mints.
- **`Revoke` is opt-in, not always a no-op (#97 follow-up).** Unlike AWS STS / Azure /
  GCP — which genuinely have no safe early-revoke mechanism (see "Cross-backend
  revocation survey" below) — Kubernetes TokenRequest tokens support
  `spec.boundObjectRef`: the API server checks the bound object's live existence + UID
  on every request, independent of the token's own `exp` claim. Setting
  `"revocable":true` in the config makes `Issue` create a dedicated, per-lease `Secret`
  and bind the token to it; `Revoke` then deletes that `Secret`, which invalidates the
  token immediately. This is **off by default**: it requires the calling identity to
  also hold `create`+`delete` on `secrets` in the namespace (on top of `create` on
  `serviceaccounts/token`), so it must be a deliberate per-config choice, not a silent
  new requirement for every existing deployment. The bound object is scoped to one
  lease, so revoking it has no effect on other leases or on the ServiceAccount itself.
- **JSON "admin DSN".** The encrypted config carries
  `{"namespace","service_account","audiences"?,"revocable"?}`. When
  `api_server`/`ca_cert`/`token` are omitted the engine uses the standard **in-cluster**
  configuration (the mounted service-account token and CA) — so no credentials live in
  Keyorix config when the server runs in the cluster. The calling identity must hold
  `create` on the `serviceaccounts/token` subresource for the target ServiceAccount.
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

### Cross-backend revocation survey (#97 residual)

Every cloud-IAM backend previously documented its no-op `Revoke` as "inherent to
self-expiring token types." Re-investigated per-backend, that turned out to be true
for three of the four, but not for Kubernetes:

- **AWS STS** (`sts:AssumeRole`): AWS has no "revoke this one session" API. The
  documented workaround (the IAM console's "Revoke active sessions," an
  `aws:TokenIssueTime`-conditioned `Deny` policy) is scoped to the *role*, not a
  session — it would deny every concurrent session on that role, not just the one
  being revoked. Left as a no-op; the blast radius is unacceptable to automate.
- **Azure** (`DefaultAzureCredential.GetToken`): a client-credentials-style flow with
  no refresh token and no per-token revoke API; Microsoft's session/refresh-token
  revocation mechanisms apply to delegated user-session flows, not this one. Left as
  a no-op.
- **GCP** (`iamcredentials.generateAccessToken`): mints a short-lived OAuth2 token,
  not a downloadable service-account key (keys CAN be deleted for immediate effect,
  but this backend never creates one). Google's IAM Credentials API documentation is
  explicit that these tokens cannot be revoked before natural expiry. Left as a no-op.
- **Kubernetes** (`TokenRequest`): supports `spec.boundObjectRef`, which the API
  server enforces live on every request — see above. Fixed via the opt-in
  `"revocable":true` config, scoped to one lease at a time.

`CredentialEngine.RevokeInvalidatesCredential(adminDSN)` lets `RevokeLease`'s audit
trail distinguish "this specific lease's `Revoke` was a real provider-side kill" from
"self-expiring, still live" instead of assuming every ephemeral backend is a no-op.

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
  ServiceAccounts — an operator concern, documented in the CLI help. Opting a config into
  `"revocable":true` additionally needs `create`+`delete` on `secrets` in that namespace.
