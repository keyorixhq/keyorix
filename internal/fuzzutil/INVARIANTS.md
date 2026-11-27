# internal/fuzzutil invariants

Read this before changing `internal/fuzzutil` itself (`Guard`, the stall monitor,
`Wait`/`WaitBounded`/`OverDeadline`, the swarm helpers). The subpackages
(`complexity`, `resguard`, `boundedwork`, `grammar`, ...) keep their own
`INVARIANTS.md`. fuzzutil is imported only from test code and test-only helper
packages (`resguard`, `fuzz/thirdparty/internal/...`) and runs
INSIDE the closures that the cost oracles measure, so its own allocations are
charged to whichever input happens to call it.

Format: `INV-FUZZUTIL-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-FUZZUTIL-<slug>.md`, one per file.
