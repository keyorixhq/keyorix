# fuzz/thirdparty invariants

Read this before changing anything under `fuzz/thirdparty`. These are
hostile-input and reachability-first fuzz harnesses pointed at *third-party*
code that Keyorix calls on attacker- or operator-influenced input (see
`scripts/fuzzing/reachgen`). The harnesses assert nothing about Keyorix's own
logic — the oracles live in each target and guard a property of the dependency
*as Keyorix uses it*. The invariants here record what each oracle checks AND,
deliberately, what it does not, so a green run is never mistaken for more than
it proves.

Format: `INV-THIRDPARTY-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-THIRDPARTY-<slug>.md`, one per file.
