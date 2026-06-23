# ADR-059: By-reference secret value read

## Status

Accepted.

## Context

Reading a secret's value over the API requires its numeric ID
(`GET /api/v1/secrets/{id}?include_value=true`). Resolving a human-readable
`environment/name` to that ID takes a separate list call, which integrations that issue a
single templated request cannot do. The External Secrets Operator (ADR — see
[docs/k8s-eso.md](k8s-eso.md)) is the motivating case: its Webhook provider performs one
`GET` and extracts the value by JSONPath, so it could only reference secrets by raw
numeric ID — poor ergonomics for a secrets product.

A by-reference read must not become a second, weaker way to read values: it has to go
through the exact same authorization, `max_reads`, suspension, and audit path as the
by-id route.

## Decision

Add `GET /api/v1/secrets/value?ref=project/environment/name` returning the secret's
value, reusing the existing secure read path end-to-end.

- **Three-level reference.** `project/environment/name`. Only project names are globally
  unique; an environment named `prod` can exist in several projects, so a two-level
  `prod/name` would be ambiguous. The secret name may itself contain slashes. Resolution
  is a pure lookup (`ResolveSecretRef`) with no value read and no read-count side effect.
- **Authorization is unchanged.** A new scope resolver (`ScopeFromRefQuery`) resolves the
  referenced secret's project/environment and hands it to the standard
  `RequireScopedPermission("secrets.read", …)` gate — so a caller scoped to another
  project is denied exactly as on the by-id route, for both users and machine
  identities. A malformed reference is a 400; an unresolved one is a 404 to
  globally-permitted callers and a 403 otherwise (existing existence-hiding behaviour).
- **Same read machinery.** The handler reads the value via the same
  `GetSecretValue` / `GetSecretValueWithPermissionCheck` methods (max_reads, suspension,
  decryption) and writes the same `secret.read` audit entry as `GetSecret`. The response
  shape is `{"data":{"secret":…,"value":…}}`, so the value is at JSONPath `$.data.value`.

## Alternatives considered

- **Two-level `environment/name`** (as the k8s sync agent's client-side resolver uses).
  Rejected for the server endpoint: ambiguous across projects, and resolving "the first
  match" would let the resolved scope depend on iteration order — a correctness and
  authorization hazard.
- **`?project_id=&ref=environment/name`.** Rejected: mixing an ID and names is clumsier to
  template than a single self-contained string.
- **A bespoke read path.** Rejected: a second value-read path risks drifting from the
  by-id route's controls. Reusing `GetSecretValue` keeps a single audited, rate-limited
  implementation.

## Consequences

- Integrations (ESO, scripts) can read by `project/environment/name` in one call; the
  ESO docs now show this as the recommended reference form.
- No new authorization surface: the endpoint is a thin resolver in front of the existing,
  tested read path. The reference resolution lists projects/environments by name, which
  is acceptable for the lookup but is not a hot path.
