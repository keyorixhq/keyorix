# ADR-035: Dynamic secrets (on-demand database credentials)

**Status:** Accepted
**Date:** 2026-06-12

## Context

Keyorix stored only *static* secrets: a long-lived value an operator writes once
and rotates on a schedule (ADR-rotation). For databases this leaves a standing
credential that every consumer shares and that survives long after a given task
finished — the blast radius of a leak is the whole credential's lifetime. The
established answer (Vault's database-secrets-engine) is **dynamic secrets**: mint
a fresh, narrowly-scoped credential per request, hand it out once, and revoke it
automatically at a short TTL. This directly supports least-privilege and
short-lived-credential expectations in the certification track (NIS2 Art. 21,
ENS `op.acc.*`).

## Decision

Add a **dynamic-secrets engine** that mints short-lived PostgreSQL credentials on
a target database and auto-revokes them at expiry.

- **Config (the target).** An operator registers a `DynamicSecretConfig` scoped to
  a project/environment: the **admin DSN** (a privileged connection used only to
  create/drop roles), a backend type (`postgres`), an optional SQL
  `creation_template` (`{{name}}` → the generated role, e.g. to `GRANT` it
  privileges), and a default TTL. The admin DSN is **encrypted at rest** via the
  server's `encryption.Service` (the same seam wired for MFA in ADR-034;
  passthrough when encryption is disabled). It is never returned by the API.
- **Issue (the lease).** `POST …/configs/{id}/issue` connects with the admin DSN,
  creates a role `kx_dyn_<random>` with a random password and `VALID UNTIL` the
  TTL, runs the creation template, and persists a `DynamicSecretLease` (status
  `active`, an opaque single-use-style `lease_id`, the encrypted credential, and
  `expires_at`). The plaintext username/password are returned **once**; only the
  encrypted form is stored.
- **Revoke.** `POST …/leases/{leaseID}/revoke` drops the role on the target
  (terminating its backends, reassigning/dropping owned objects, `DROP ROLE`) and
  marks the lease `revoked`. If the target drop fails the lease is flagged
  `revoke_failed` with the error, surfacing it to an operator rather than being
  silently lost.
- **Auto-revoke sweep.** An opt-in background sweeper
  (`dynamic_secrets.sweep_enabled`) revokes every `active` lease past its
  `expires_at` on a configurable cadence (default 1m), system-actored — mirroring
  the ADR-032 retention scheduler. This is what makes the credentials genuinely
  short-lived even if no client calls revoke.
- **Authorization** reuses `secrets.read` / `secrets.write`, scoped in-handler to
  each config/lease's project/environment. No new permission is introduced.
- **Audit:** `dynamic_secret.config_created`, `dynamic_lease.issued`,
  `dynamic_lease.revoked`, `dynamic_lease.revoke_failed`.

## Why PostgreSQL only (for now)

The target backend is the database whose credentials are minted — distinct from
Keyorix's own store (which is Postgres *or* SQLite). SQLite has no role/login
concept, so dynamic credentials are meaningless there. The engine is behind a
`CredentialEngine` interface with a `New(backendType)` factory, so MySQL and
others can be added without touching the core, HTTP, or storage layers.

## Security properties

- **Admin DSN and issued credentials encrypted at rest**, never logged, never
  echoed back by the API.
- **Roles are identifier-sanitized** (`pgx.Identifier.Sanitize`) and the password
  is drawn from `crypto/rand`; the backend-termination query is parameterized.
- **Short-lived by construction** — a role carries `VALID UNTIL` *and* is dropped
  by the sweep, so a missed client-side revoke still bounds exposure to one TTL.
- A failed encryption/persist after issue **revokes the just-created role** so a
  partial issue never leaks a live credential.

## Verification

Core tests against real SQLite + an enabled encryptor and a fake engine: admin
DSN ciphertext at rest; issue → lease persisted `active` with the credential
encrypted; list; revoke → role dropped + status `revoked`; double-revoke
rejected; backdated lease swept → `revoked`/`expired`; a target revoke failure →
`revoke_failed` flagged; issue against an unknown config rejected. `make build` +
full suite + `go vet` green.

## Deferred

MySQL/other backends; renewable leases (extend TTL in place); per-config max-TTL
ceilings; a CLI surface; returning leases a caller can enumerate across configs.
