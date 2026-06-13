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

Other backends (Mongo, cloud IAM); returning leases a caller can enumerate across
configs; a gRPC surface. (Renewable leases, per-config max-TTL ceilings, and a
`keyorix dynamic-secret` CLI have since shipped — see the addenda.)

## Addendum (2026-06-12): MySQL target engine

A `mysql` backend now implements the same `CredentialEngine` interface
(`internal/dynamic/mysql.go`); `key_provider`-style selection is via the config's
`backend_type`. It mints `kx_dyn_<random>'@'%` accounts (`CREATE USER … IDENTIFIED
BY …`), runs the creation template with `{{name}}` → the quoted account reference,
and on revoke kills the account's live sessions then `DROP USER`. Username and
password come from the same quote-free `crypto/rand` alphabet, so the documented
SQL-injection trust boundary is unchanged.

**One difference from PostgreSQL:** MySQL accounts have no `VALID UNTIL`
equivalent that disables them at a timestamp, so a MySQL lease's TTL is enforced
**only** by the auto-revoke sweeper (`dynamic_secrets.sweep_enabled`) — the
sweeper should be enabled when using MySQL targets, otherwise a credential lives
until an explicit revoke. The Postgres engine remains belt-and-suspenders (role
expiry **and** sweep). The MySQL driver (`go-sql-driver/mysql`, pure Go) links
into the server; no cloud SDK is added.

## Addendum (2026-06-12): lease lifecycle — max-TTL ceiling + renewal

Two of the originally-deferred items shipped together:

- **Per-config max-TTL ceiling** (`DynamicSecretConfig.MaxTTLSeconds`, 0 = none).
  Caps the lifetime of any lease from the config regardless of the TTL a caller
  requests: the issue TTL is clamped to it, and config creation rejects a
  `default_ttl_seconds` greater than `max_ttl_seconds`. A real safety control —
  it bounds credential exposure even if a caller asks for a long TTL.
- **Renewable leases** — `POST …/leases/{leaseID}/renew {ttl_seconds}` extends an
  **active** lease's expiry (a new `CredentialEngine.Renew` pushes PostgreSQL's
  `VALID UNTIL` forward; MySQL is a no-op enforced by the sweep). Renewal is
  **capped** so a lease's total lifetime from issue can never exceed the config's
  max-TTL — a renewal that wouldn't extend (cap reached) is rejected. Audited as
  `dynamic_lease.renewed`. Renewal reduces credential churn vs. re-issuing while
  the max-TTL keeps the hard bound on exposure.
- **Incident kill switch** — `POST …/configs/{id}/revoke-all` (and
  `keyorix dynamic-secret revoke-all <config-id>`) revokes **every** active lease
  from a config at once, for when a target DB or config is compromised. Same
  `secrets.write` + per-project-MFA authorization as a single revoke; best-effort
  per lease; audited `dynamic_secret.bulk_revoke` with revoked/failed counts.

## Addendum (2026-06-12): MongoDB target engine

A `mongodb` backend now implements the same `CredentialEngine` interface
(`internal/dynamic/mongodb.go`), selected via the config's `backend_type`. It mints
`kx_dyn_<random>` users in the target's `admin` database (`createUser`) and drops
them on revoke (`dropUser`, idempotent — `UserNotFound` is treated as already gone).
The admin DSN is a MongoDB connection URI; the creation template is an
operator-authored **JSON role spec**
(`{"roles": [{"role": "readWrite", "db": "app"}, "clusterMonitor"]}`) rather than an
SQL grant — the only interface difference from the SQL engines. Username and
password are `crypto/rand` and are sent as **typed BSON values** to `createUser`, so
a generated credential can never be interpreted as a command — credential injection
is structurally impossible; the role spec is the trust boundary.

**Like MySQL**, MongoDB users carry no `VALID UNTIL`, so a lease's TTL is enforced
**only** by the auto-revoke sweeper (`dynamic_secrets.sweep_enabled`) — enable it
for MongoDB targets; `Renew` is therefore a no-op (the sweep enforces the new
expiry). The MongoDB driver (`go.mongodb.org/mongo-driver`, pure Go) links into the
server; no cloud SDK is added. Keyorix now mints dynamic credentials for
PostgreSQL, MySQL, **or** MongoDB.

### Lease-lifecycle fail-open fixes (hardening, 2026-06-12)

An internal audit surfaced two fail-opens, both fixed:

- **TTL enforced or refuse to issue.** Backends without a DB-level expiry
  (`SupportsNativeExpiry() == false`: MySQL, MongoDB) rely entirely on the
  auto-revoke sweeper. `IssueLease` now refuses to mint from such a backend when
  `dynamic_secrets.sweep_enabled` is off — otherwise the credential's advertised
  TTL would never be enforced (it would live forever on the target). PostgreSQL
  (`VALID UNTIL`) is unaffected and issues regardless.
- **No invisible orphans.** If a post-mint step fails (encryption / token-gen /
  lease persistence), the just-minted role is dropped; if that drop *also* fails,
  a `revoke_failed` lease row is now recorded (capturing the role name) and
  audited, so the orphaned live credential is visible to an operator instead of
  being permanent and untrackable (every list/sweep/revoke path keys off the lease
  table).

## Addendum (2026-06-13): Redis target engine

A `redis` backend now implements the same `CredentialEngine` interface
(`internal/dynamic/redis.go`), selected via the config's `backend_type`. It mints a
short-lived Redis **ACL user** (`ACL SETUSER kx_dyn_<random> on >password <rules>`)
and drops it on revoke (`ACL DELUSER`, idempotent — returns the count removed).

The admin DSN is a Redis URI (`redis://:pass@host:6379/0`, or `rediss://…` for TLS)
for a user holding the `+acl` command; the creation template is operator-authored,
whitespace-separated **ACL rule tokens** (`~app:* +@read +@write`). The generated
username and password are passed to `ACL SETUSER` as **discrete command arguments**
(RESP bulk strings), never string-interpolated, so the credential can never be
parsed as an ACL token — credential injection is structurally impossible (the same
guarantee MongoDB gets via typed BSON); the ACL rule tokens are the operator-
authored trust boundary. The pure-Go `redis/go-redis/v9` client links into the
server; no cloud SDK is added.

**Like MySQL and MongoDB**, Redis ACL users carry no native expiry, so a lease's TTL
is enforced **only** by the auto-revoke sweeper (`SupportsNativeExpiry() == false`)
— issuing is refused while the sweeper is disabled (the lease-lifecycle hardening
above), and `Renew` is a no-op. Keyorix now mints dynamic credentials for
PostgreSQL, MySQL, MongoDB, **or** Redis.

## Deferred (updated)

Cloud-IAM backends (AWS STS / GCP / Azure), which need a non-DSN credential shape
beyond the current `CredentialEngine` interface; per-config connection pooling for
the admin connection; gRPC/UI surfaces for lease management.
