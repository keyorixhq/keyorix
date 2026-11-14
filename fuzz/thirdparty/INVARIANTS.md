# fuzz/thirdparty invariants

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
