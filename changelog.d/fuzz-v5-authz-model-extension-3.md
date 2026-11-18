### Security

- `server/authzdiff`: bind four bulk-secret operations into the authorization
  differential — `bulk.delete` (secrets.delete@project), `bulk.rename`,
  `bulk.suspend`, and `resume.all` (secrets.write@project). Each op is validated
  by `TestV5ext3StrictSweep` (curated-variation strict sweep, 0 unexplained)
  and `TestBulkSecretRouterGatesPresent` (structural gate-presence check, red
  on gate removal). The per-item RBAC fallback (#r124) is confirmed to agree
  with the router gate for all standard-sweep principals. Two waivers added:
  `known-10` (machine actors get 400/500 from actorID=0 business rule) and
  `known-11` (bulk.delete per-item read prerequisite not in router gate model).
  Differential plants are not applicable for ops where the per-item RBAC
  mirrors the router gate (gate removal changes HTTP status 403→200+empty, not
  the allowed/denied classification). REST coverage: 101 → 105 of 212.
  Deferred: `bulk.rotate` (fixture-blocked), SCIM, MFA step-up.
