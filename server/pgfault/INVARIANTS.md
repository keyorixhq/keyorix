# server/pgfault INVARIANTS

Rules the pgfault real-PostgreSQL fault harness must keep. This package is
**test-only** (every file is `_test.go`; no production code is built from it):
it drives keyorix's real audit-commit path against a real PostgreSQL server
through a TCP fault proxy and asserts durability oracles survive a connection
cut or stall at any point of the v3 wire protocol. See `proxy_test.go` and
`commit_oracle_test.go` headers for scope and for what it does
*not* cover (classes b/c need a cluster this host cannot start).

Read this before changing the proxy framing, the oracle definitions, or the
isolation/safety wiring.

New invariants go in `INVARIANTS.d/INV-PGFAULT-<slug>.md` (one per file), not
appended here.

Format: `INV-PGFAULT-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.
(This package uses only slug-ID fragments under `INVARIANTS.d/`; this file
exists to declare the prefix and hold shared context.)
