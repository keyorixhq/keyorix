- **INV-HTTP-denial-cost-existence-independent** Extends
  INV-HTTP-denial-status-existence-independent along the dimensions that invariant lists as
  "not covered (timing/length side channels)". For an actor with no authority over the target
  (zero role grants, or an expired grant), a denied single-id `GET`/`DELETE` is indistinguishable
  between an existing-but-forbidden id and a same-shape absent id not only in HTTP status but
  also in: the normalised typed-error text (`error`+`message`, ids stripped), a response-body
  LENGTH bucket, and the information-bearing response headers (`Location`, `Retry-After`,
  `WWW-Authenticate`, rate-limit counters, `Set-Cookie` presence). These four dimensions are
  GATED. A DETERMINISTIC COST proxy — the resguard `DBMeter` per-request DB query count and rows
  touched, read as a metamorphic delta so common per-request overhead cancels — is also measured
  but REPORTED, NOT gated: the scoped-secret routes legitimately issue more DB round-trips when
  the secret EXISTS (the `RequireScopedSecretPermission` lookup loads the row and resolves its
  scope before denying) than when it is absent (the lookup misses and short-circuits), so the
  query-count differs by existence by design. That residual is a DB-round-trip asymmetry, not a
  response difference, and ADR-096's 403-for-both equalizes the RESPONSE, not the work — a
  hardening observation, recorded for the report. Why: oracle 7 proved only status equality and
  named length/timing as a gap; an enumeration attacker who controls the id can also read a body
  length or a header. Guard: `TestEX1ExistenceCostCensus` (deterministic, every qualifying op ×
  each zero-authority principal, each metamorphic pair replayed 3× and only differences present
  in all three runs are reported — robust to async deny-audit noise) and `FuzzEX1ExistenceCost`
  (fuzzes the id ENCODING: leading zeros, `+`-sign, URL-encoded digits, fullwidth-Unicode digits,
  hex, trailing junk — ~441k execs found no client-observable divergence). Pure detector
  `ex1Compare` red/green-proofed per dimension in `TestEX1CostDetector_RedGreen`; a planted
  not-found→404 in `handleScopeResolutionError`'s non-global-holder branch was caught as 114
  diverging (status+errtext+length) findings (reverted, never committed). Not covered: real
  network/CPU wall-clock timing (only DB round-trip COUNT is metered, never wall time); the login
  path's DB-cost (its deny-audit writes are async `goSafe`, so a synchronous snapshot is
  unreliable — only its client-observable response equality is asserted, in
  `TestEX1AccountExistenceOracle`); caching/rate-limit/WAF layers in front of the server;
  server-side DB work (triggers/CTEs the `DBMeter` cannot see).
