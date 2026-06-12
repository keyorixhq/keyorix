# ADR-027 — Personal Access Tokens

**Status:** Decided (June 2026)
**Author:** Andrei Beshkov
**Related:** ADR-021 (two-tier permission model). Introduced with the My Account page.

---

## Context

The My Account page needs user-owned API credentials: a developer should be able to
mint a long-lived token from the UI and use it as a bearer credential for CLI/CI
access, then revoke it themselves. Two things were missing:

1. **No self-service token exists.** `APIClient`/`APIToken` (service accounts) are
   admin/system-wide and gated behind `users.read`/`users.write`. A regular user
   cannot create or manage them.
2. **No API-token auth path exists at all.** The auth middleware validates only
   opaque session tokens. Service-account `APIToken`s are created but never checked
   on an incoming request — there is no code that authenticates a request by a
   non-session token. So personal access tokens (PATs) are the *first* working
   token-auth credential in the system.

## Decision

Add a dedicated, self-scoped **Personal Access Token** credential.

### New model, not a reuse of `APIToken`
`PersonalAccessToken` is its own table: `UserID`, `Name`, `TokenHash` (unique index),
`TokenPrefix`, `LastUsedAt`, `ExpiresAt`, `Revoked`, `CreatedAt`. `APIToken` is bound
to a service-account `ClientID` and lives in the admin domain; entangling self-service
tokens with it would couple two different lifecycles and authorization models.

### SHA-256 hashing, not bcrypt
The stored value is the **SHA-256 hex** of the raw token. PATs are high-entropy random
secrets (32 random bytes), so a fast hash is appropriate — and, decisively, it allows an
**indexed equality lookup** (`WHERE token_hash = ?`) on every authenticated request.
bcrypt would force a full-table scan on the hot path. The raw token is shown exactly once
on creation and never persisted.

### `kx_pat_` prefix
Raw tokens are `kx_pat_<base64url(32 random bytes)>`. The prefix is load-bearing:
- the auth middleware routes a bearer token to PAT validation iff it starts with `kx_pat_`;
- secret scanners can detect a leaked Keyorix PAT by its prefix.
Session tokens keep their hex format, so prefix discrimination is unambiguous.

### Middleware integration
`validateToken` routes by prefix: `kx_pat_*` → `ValidatePATToken`, otherwise
`ValidateSessionToken`. **Both produce an identical `UserContext`** (UserID / Username /
Email / Roles). Because a PAT resolves to its owner's identity, the existing SHA-256
token cache and all downstream per-scope `core.Authorize` checks work unchanged — there
is no separate authorization path for PATs.

### Full-permission inheritance (v1 limitation)
A PAT inherits the **complete** permission set of its owner. There is no per-credential
scoping: `core.Authorize` resolves permissions per request from the user's role
assignments at the target scope, and there is no enforced mechanism to attach a reduced
set to a credential. The token `Name` is the audit/identification handle. **A PAT can do
everything its owner can do** — surfaced in the create response and the UI. Real PAT
scoping is deferred to a later ADR.

### Revocation latency
Revoking a PAT marks `Revoked = true`. The auth cache keys on `SHA-256(token)` with a
30s positive TTL and we do not retain the plaintext, so a revoked PAT may remain valid
for up to ~30s until its cache entry expires — identical to the existing session-logout
window. Acceptable and consistent with the session model.

### `last_used_at` write throttling
`last_used_at` is **not** written on every request (that would turn each authenticated
read into a write and defeat the token cache). It is updated best-effort, at most once
per 30s per token, via a conditional `UPDATE ... WHERE last_used_at < now-30s`. The same
throttling applies to session `last_seen_at`.

## Consequences

- Users can self-manage API credentials from My Account; CLI/CI can authenticate as a
  user without a browser login.
- The middleware now has a token-type dimension, but it is a single prefix branch with a
  shared result shape — low complexity.
- The full-permission-inheritance limitation must be communicated clearly until scoping
  lands; a leaked PAT is as powerful as the owner's session.
  **Update (ADR-042):** optional per-token least-privilege scoping has now landed — a
  PAT may carry a permission allowlist and/or a single-project confinement that narrows
  it below its owner. Full inheritance remains the default for back-compat.

## What this is not

- Not service accounts (those remain admin-managed, see `service_accounts_handler.go`).
- ~~Not scoped/least-privilege tokens (deferred).~~ **Scoped tokens shipped in ADR-042.**
- Not OAuth/OIDC tokens (separate M2 work).
