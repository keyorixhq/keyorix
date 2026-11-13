# diffkit invariants

Invariants for the reusable differential-fuzzing kit (`fuzz/diffkit`). The kit
compares two or more independent implementations of one security decision and
reports a disagreement that no documented-differences row explains. Read this
before changing `diffkit.go` or `minimize.go`.

New invariants go in `INVARIANTS.d/INV-FUZZDIFF-<slug>.md`, one per file (see
`docs/invariants-fragments.md`).

Format: `INV-FUZZDIFF-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## Oracle

Rules about when a divergence is, and is not, reported.

## Isolation

Rules about the kit surviving a misbehaving implementation.
