# internal/fuzzutil/grammar invariants

Read this before changing anything in `internal/fuzzutil/grammar`. It is a
structure-aware input generator imported only from `_test.go` fuzz files: it turns
a fuzzer's `[]byte` into a DER/XML tree plus a mutation set and serialises that
tree back to bytes, so the `go test -fuzz` engine mutates structural *choices*
rather than raw octets. It asserts nothing itself — the oracles live in the fuzz
targets that consume it — so the only properties it must keep are the ones a fuzz
harness relies on: it must never be the thing that crashes, and its "clean" output
must actually be well-formed (otherwise a target can never reach the parser it is
meant to exercise, and a green run would be meaningless).

Format: `INV-GRAMMAR-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-GRAMMAR-<slug>.md`, one per file.
