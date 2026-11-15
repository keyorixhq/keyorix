- **INV-HTTP-denial-status-existence-independent** For an actor with no authority over the
  target — a logged-in user holding zero role grants, or a user whose only grant has expired —
  a denied single-id `GET`/`DELETE` returns the SAME HTTP status whether the target id exists
  or not. A `403`-for-existing / `404`-for-absent split is an existence oracle: it lets an
  unauthorized caller probe which ids exist. This holds both where a coarse group-permission
  gate denies uniformly (roles, users, …) AND on the scoped-secret routes (`GET /secrets/{id}`
  and its versions/ACL/audit/accessor siblings, `DELETE /secrets/{id}`), where
  `RequireScopedSecretPermission` is the only gate and looks up the secret BEFORE authorizing —
  so it must answer a missing secret with the same scope-resolution deny as an unauthorized one
  (`handleScopeResolutionError` with `defaultDenyMessage`, `server/middleware/auth.go`), not a
  distinct `404`. Why: the documented contract (`components.responses.SecretReadRefused`: "any
  other caller gets the same 403/404 as for a secret it cannot see") and the enforced instances
  INV-HTTP-zero-grant-reads-nothing / INV-HTTP-scim-failure-never-not-found; this is their
  repo-wide, fuzz/census-level generalisation across every single-id GET/DELETE. Guard:
  `TestOSFDenialExistenceCensus` (deterministic — for every qualifying op and each
  zero-authority principal, probes an existing vs a guaranteed-absent id and asserts equal
  denial status) and oracle 7 (`osOracleDenialExistence`) in `FuzzOpenAPIStateful` (candidate
  by default; fatal under `KEYORIX_OSF_STRICT=1`). Red-proofed: a planted not-found→distinct-404
  in `RequireScopedSecretPermission`'s lookup-miss branch was caught as 36 diverging
  (op,principal) pairs across the scoped-secret surface (reverted, never committed). Not
  covered: existence independence for AUTHORIZED actors (200-vs-404 is correct for them); the
  cross-tenant fine-grained case of an actor who passes a coarse gate but is denied a specific
  object in another tenant (the viewer→project-B case — covered by the SecretReadRefused
  contract tests, not re-driven here because it needs per-op target knowledge the schema does
  not express); ops with zero or multiple numeric id path params; POST/PUT/PATCH (a body 400
  precedes the id lookup); which of the two equal statuses is the right one (only equality);
  timing/length side channels.
