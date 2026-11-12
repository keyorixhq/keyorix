### Testing
- **Schema-driven stateful OpenAPI fuzzer (`FuzzOpenAPIStateful`, `server/http`).** Enumerates
  all 307 operations straight from `openapi.yaml` (kin-openapi), generates request arguments from
  the schemas (valid / boundary / schema-violating), binds ids returned by one call into later
  calls' path params and `*_id` body fields (a successful DELETE feeds the use-after-delete
  shapes), and drives 1–12 operation sequences against the real in-process `NewRouter` stack over
  a seeded SQLite store with eight fixed principals (no-token, garbage, no-role, viewer,
  project-admin, global-admin, machine-token, expired-grant). Five oracles — no undeclared 5xx,
  response conformance, unauthenticated-layer authorization monotonicity, canary non-leakage, and
  idempotent reads — each red/green-proven and each documenting what it does NOT verify. Added
  its `scripts/fuzzing/targets.d/` entry.
