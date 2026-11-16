# scripts/e2e/mp1 invariants

Rules the MP1 multi-process PostgreSQL race harness must keep. Each is a
cross-replica HA property of Keyorix (ADR-039) that an oracle in this package
checks against several real `keyorix-server` processes sharing one Postgres
database. A change here must not weaken an oracle into something that passes
whether or not the property holds (CLAUDE.md: "a guard nobody has watched fail
is not a guard"). Every oracle's decision logic has a red/green proof in
`redproof_test.go`; the restart half of the killed-replica invariant is a
liveness check (a failed boot or write fails the test) with no separate red
proof.

No CI job runs this package with `-tags e2e` against Postgres: every guard
below holds only for manual runs (`KEYORIX_TEST_PG_DSN=... go test -tags e2e
-p 1 -parallel 1 ./scripts/e2e/mp1/`).

Live fuzzing needs `-parallel 1` (or a small value): each fuzz worker process
boots its own 3-replica cluster, and the default worker count (GOMAXPROCS)
exhausts the connection slots of a shared Postgres (SQLSTATE 53300).

New invariants go in `INVARIANTS.d/INV-MPRACE-<slug>.md` (one per file); see
`docs/invariants-fragments.md`.

Format: `INV-MPRACE-<slug> <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## Uniqueness

## Serial equivalence and visibility

## Revocation

## Audit

## Advisory locks and crash recovery

## Confidentiality
