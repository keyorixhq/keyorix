# server/authzdiff invariants

Read this before changing anything in `server/authzdiff`. It is a test-only
cross-layer authorization differential harness: one fuzzer-chosen case runs on
core, the real REST router and the real gRPC server, each on its own fresh seeded
database, and two oracles check them — Oracle 1 (the layers agree) and Oracle 2
(each layer matches an independent reference model that re-derives the
authorization decision from the grant tables by raw SQL, never through the code
under test). `MATRIX.md`/`matrix.json`, `COVERAGE.md`/`COVERAGE-ALL.md`,
`OUTCOMES.md` and `SEQUENCE.md` are the generated and reference material.

Format: `INV-AUTHZDIFF-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-AUTHZDIFF-<slug>.md`, one per file.
