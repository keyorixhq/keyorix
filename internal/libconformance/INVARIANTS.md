# internal/libconformance invariants

Read this before changing anything in `internal/libconformance`. The package has no
non-test code (see `doc.go`): it holds fuzz targets that pin the behaviour Keyorix relies
on in third-party parsing/crypto libraries, calling only the libraries so the fuzz
binary's coverage map stays small. The DF1 cross-library parser-differential targets live
here: each feeds ONE input to two independent library readings and fails on a disagreement
that is not on an EXPECTED-DIFFERENCE allowlist (reason per entry), with a companion
dead-entry test so a stale allowlist row cannot hide a regression.

Format: `INV-LIBCONFORMANCE-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## DF1 cross-library parser differentials

New invariants go in `INVARIANTS.d/INV-LIBCONFORMANCE-<kebab-slug>.md`, one per file.
