# ADR-047: Backend rotation executors

## Status

Accepted. PostgreSQL, MySQL, MongoDB, and Redis (password-set) plus AWS IAM, GCP
service-account keys, and Azure AD app secrets (generate-upstream) executors shipped and
wired into the auto-rotation flow: a secret
with `rotation_backend` + `rotation_ref` set has its new value applied upstream (the
executor) before being stored in Keyorix, so the two never drift — and the value is NOT
stored if the upstream apply fails. Manageable over HTTP/gRPC/CLI (scoped
`secrets.write`). MySQL is the second backend (`ALTER USER … IDENTIFIED BY`, with
account names/passwords emitted as doubled-quote/backslash literals — injection-safe
under both default and NO_BACKSLASH_ESCAPES sql_modes). Cloud-key APIs (KMS/IAM)
would need a different contract (the cloud *generates* the new key rather than accepting
one). That contract now exists as `rotation.GeneratingExecutor` (`GenerateUpstream(ref)
→ value`): the rotation flow prefers it over `Rotate`, storing the value the upstream
minted. The first such backend is **AWS IAM** — rotating a user's access key by minting
a fresh pair (deleting prior keys) and storing `{access_key_id, secret_access_key}` as
JSON. Credentials come from the ambient AWS chain; the same fail-closed `allowed_refs`
guardrail (on IAM usernames) applies.

## Context

Automated rotation (ADR-046) regenerates a secret's value in Keyorix and stores it as a
new version. That is correct only for **Keyorix-owned** secrets — values that exist
solely in Keyorix, where consumers read the current value on each use. It deliberately
refuses to touch a secret that mirrors an **external** credential (a database user's
password, a cloud access key), because changing the Keyorix copy would desynchronize it
from the upstream and break everything that authenticates with the real credential.

That leaves the most valuable rotation case — the long-lived shared credential teams
actually worry about — still manual. To auto-rotate those, rotation must also **apply
the new credential to the upstream system**.

## Decision

Introduce **rotation executors**: a backend that, given a reference and a freshly
generated value, sets that credential in the upstream system. The full rotation of an
externally-owned secret then becomes: generate a new value → executor applies it
upstream → Keyorix stores it as a new version (the existing ADR-046 step).

- **Interface seam.** `rotation.Executor { Name(); Type(); Rotate(ctx, ref, newValue) }`,
  with the backend driver/SDK contained behind the implementation (and a fake-able inner
  seam for unit tests), mirroring Keyorix Connect's connector model (ADR-043) and the
  dynamic-secrets engines (ADR-035). A `rotation.Manager` is the name→executor registry.
- **First backend: PostgreSQL.** `Rotate(role, newPassword)` runs
  `ALTER ROLE <role> WITH PASSWORD <pw>` against an admin connection. The role name is
  quoted as an identifier and the password as a string literal (both escaped), so
  neither can break out of the statement (DDL can't bind parameters).
- **Admin credentials come from the operator, never from a secret.** Each configured
  backend names an environment variable holding its admin DSN
  (`KEYORIX_ROTATION_<NAME>_DSN`-style); the DSN is read from the environment, not the
  config file — the same trust model as Connect backends and dynamic-secrets engines
  (ambient/operator-provided credentials with enough privilege to rotate, scoped tightly
  by the operator).
- **`allowed_refs` guardrail — REQUIRED (fail-closed).** A backend carries a prefix
  allowlist of the refs (role names) it will rotate. Unlike Connect's optional
  allowlist, a rotation backend **must** declare one: a backend with no `allowed_refs`
  is refused at registration, and the executor itself refuses to rotate when the list is
  empty. This is load-bearing — pointing a secret's `rotation_ref` is gated only by
  scoped `secrets.write` on that secret, so without the allowlist a writer could drive
  `ALTER ROLE` against any principal the admin DSN can reach. The allowlist (operator-
  chosen, safe-to-rotate prefixes) is what bounds that. Setting a secret's
  `rotation_backend` also validates the backend exists at configuration time.

This ADR's slice ships the executor subsystem (interface + manager + PostgreSQL backend)
and its configuration/wiring. A follow-up wires it into `RunAutoRotation` (a per-secret
`rotation_backend` + `rotation_ref`, used in place of the generate-only path) and adds
further backends.

## Alternatives considered

- **Reuse the dynamic-secrets engines.** Dynamic secrets *mint ephemeral* credentials
  (create-on-lease, drop-on-expiry); rotation *replaces a long-lived named* credential
  in place. Different lifecycle and SQL, though they share the "admin connection to a
  backend" shape — worth factoring later, not now.
- **Run rotation SQL through the app's GORM/pgx pool.** Rejected — the rotation admin
  connection is a distinct, more-privileged identity than the app's data-plane DB user
  and must not share the pool; it is opened per-rotation from the backend's own DSN.
- **Parameterized DDL.** Not possible in PostgreSQL (identifiers and the password in
  `ALTER ROLE` cannot be bind parameters), hence explicit identifier/literal quoting.

## Consequences

- Externally-owned secrets become auto-rotatable once the wiring lands, closing the main
  remaining rotation gap.
- A new trust surface: an admin DSN per backend. It is operator-configured, env-sourced,
  and should be scoped to exactly the principals it must rotate (plus the `allowed_refs`
  guardrail). Documented accordingly.
- The executor model is reusable: adding a backend (MySQL, a cloud key API) is a new
  `Executor` implementation behind the same seam.
