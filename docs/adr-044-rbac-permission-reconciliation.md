# ADR-044: Idempotent RBAC permission reconciliation on startup

## Status

Accepted.

## Context

RBAC permissions and the baseline role→permission grants are seeded once, on first
boot, by `BootstrapSystem` (which no-ops when any user already exists). There was no
mechanism to introduce a *new* canonical permission to an already-initialised
deployment: an upgrade that adds a permission would leave existing installs with no
role holding it, so any route gated on the new permission would be unreachable until
an operator hand-created and granted it.

This blocked, for example, giving Keyorix Connect (ADR-043) its own `connect.read`
permission instead of reusing `secrets.read` — the least-privilege improvement the
#243 review asked for — because upgraded installs would lose Connect access.

## Decision

Reconcile the canonical permission catalog on **every server startup**, additively
and **non-clobbering**:

- If the permission set is empty, do nothing — the install is pre-bootstrap, and
  `BootstrapSystem` will seed everything (including any new permission, since it
  reads the same `defaultPermissions`). This avoids colliding with first-boot seeding.
- Otherwise, for each canonical permission **that does not already exist**, create it
  and grant it to exactly the canonical roles whose definition lists it (only when
  the role exists and does not already hold it).
- Permissions that **already exist are never touched** — no grant is added or removed
  for them. This is the load-bearing safety property: an operator who deliberately
  removed a default grant (or added a custom one) keeps their customization. Only
  genuinely-new permissions flow out, and only to their baseline roles.

Reconciliation is best-effort: a failure is logged, not fatal (it must never block
startup), and it is naturally idempotent (a second run finds nothing new).

### First use: `connect.read`

`connect.read` is added to the catalog and granted to the admin roles
(`admin` / `system_admin`) by default. The Keyorix Connect routes switch from
`secrets.read` to `connect.read`, so holding native read access no longer implies
read access to external stores.

## Alternatives considered

- **A seed/migration version counter** (apply permission migrations for versions >
  current): more general (also handles renames/removals) but heavier machinery. The
  "create-if-missing, grant-only-to-new" rule covers the additive case — by far the
  common one — with no version bookkeeping and no clobbering risk.
- **Reconcile every role→permission grant to match the defaults**: rejected — it
  would re-add grants an operator deliberately removed (and couldn't express intent
  to drop a default), fighting the operator instead of helping them.

## Consequences

- Adding a new canonical permission is now safe across upgrades: list it in
  `defaultPermissions` and in the role definitions that should hold it.
- **Behavior change for Connect:** a non-admin principal that could use Connect via
  `secrets.read` now needs `connect.read` (admins are unaffected). This is an
  intentional least-privilege tightening of a recently-shipped, opt-in feature.
- New *roles* are out of scope here (only permissions reconcile); add that mechanism
  if a future release introduces a new default role that upgrades must receive.
