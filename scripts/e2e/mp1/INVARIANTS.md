# scripts/e2e/mp1 invariants

Rules the MP1 multi-process PostgreSQL race harness must keep. Each is a
cross-replica HA property of Keyorix (ADR-039) that an oracle in this package
checks against several real `keyorix-server` processes sharing one Postgres
database. A change here must not weaken an oracle into something that passes
whether or not the property holds (CLAUDE.md: "a guard nobody has watched fail
is not a guard"); every oracle below has a red/green proof in
`redproof_test.go`.

New invariants go in `INVARIANTS.d/INV-MPRACE-<slug>.md` (one per file); see
`docs/invariants-fragments.md`.

Format: `INV-MPRACE-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## Uniqueness

## Serial equivalence and visibility

## Revocation

## Audit

## Advisory locks and crash recovery

## Confidentiality
