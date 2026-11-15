# internal/fuzzutil/complexity invariants

Read this before changing anything in `internal/fuzzutil/complexity`. It is the
cost oracle for algorithmic-complexity (PerfFuzz-style) fuzzing: `Measure` runs a
function on one input and records its cost, and `Budget.Check` fails when cost
grows out of proportion to the input size. It is imported only from `_test.go`
fuzz files and imports neither `testing` nor any keyorix package. The properties
it must keep are the ones every complexity fuzz target downstream relies on: the
measurement must be accurate per call, and the ratio classifier must separate a
linear from a super-linear subject without false-firing on constant overhead.

Format: `INV-COMPLEXITY-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-COMPLEXITY-<slug>.md`, one per file.
