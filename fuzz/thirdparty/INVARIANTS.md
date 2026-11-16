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
Read this before changing the hostile-SERVER fuzz harnesses under `fuzz/thirdparty`.
These targets drive the REAL third-party clients Keyorix uses (DB drivers, and the
cloud SDKs / SMTP client under `smtp`, `awskms`, `awss3`, `azurekeys`) against a
loopback server whose replies are fuzzer-controlled, and assert sound oracles about
how those clients behave **as Keyorix constructs them**. The rules below are the
load-bearing oracle properties: a change that removes or weakens one silently turns a
guard into a comment.

These are regression tripwires on third-party behaviour at the Keyorix construction
site, not proofs Keyorix owns the behaviour — stated as such in each fragment.

Format: `INV-FUZZCLOUD-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`
(the `NN` is a placeholder — fragment IDs use a descriptive `-<slug>` suffix, not a
number, per `docs/INVARIANTS.md`'s slug convention).

New invariants go in `INVARIANTS.d/INV-FUZZCLOUD-<slug>.md`, one per file.
