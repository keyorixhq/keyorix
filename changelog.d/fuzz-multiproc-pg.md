### Testing
- **Multi-process PostgreSQL race harness (e2e).** Added a Go fuzz harness that
  boots several real `keyorix-server` processes against one shared PostgreSQL
  database (the ADR-039 HA shape) and drives them concurrently through the REST
  API, choosing cross-replica interleavings from the fuzz input. It checks
  cross-replica convergence and single-register serial equivalence per
  iteration, and carries seeded oracles for post-return visibility, revoked
  personal-access-token denial across replicas, a SIGKILLed replica leaving no
  stuck advisory lock, audit-chain verification, and a secret/key log canary.
  Each oracle has a red/green proof. Requires the `e2e` build tag and
  `KEYORIX_TEST_PG_DSN`; skips otherwise. No production code changed.
