# INVARIANTS — `scripts/fuzzing/time-travel/` (TT1 dependency time-travel differential)

The rules a change to this harness must keep. Each is linked to the test or
script-level check that enforces it, or marked `UNGUARDED` with a follow-up.
New invariants go in `INVARIANTS.d/INV-TIMETRAVEL-<slug>.md`, one per file.

Format: `INV-TIMETRAVEL-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## Oracle

The differential compares several historical versions of one library on a shared
corpus; the mutation layer coverage-fuzzes the repo-pinned ("new") version with
an older version as a subprocess oracle. The invariants below protect the two
properties that make that comparison *mean* something: that the method never
silently mutates the repo's own dependency pins, and that the mutation oracle
fails in the security-relevant direction (new-more-lenient), not on cosmetic
divergence.

See `INVARIANTS.d/` for the individual entries.
