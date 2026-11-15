# internal/libconformance invariants

This package holds differential and conformance fuzz targets that pin the behaviour
Keyorix relies on in third-party parsing / crypto / schema libraries. It has no
non-test code (see `doc.go`): the targets call only the libraries, never Keyorix
code, so the package links a minimal coverage map.

New invariants go in `INVARIANTS.d/INV-LIBCONFORMANCE-<kebab-slug>.md` (one per
file), per the root `CLAUDE.md` convention.

Format: `INV-LIBCONFORMANCE-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.
