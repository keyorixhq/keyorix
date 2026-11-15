# internal/libconformance invariants

Read this before changing anything in `internal/libconformance`. The package has no
non-test code (see `doc.go`): it holds fuzz targets that pin the behaviour keyorix relies
on in third-party parsing and crypto libraries (beevik/etree, crewjam/saml's xmlenc,
digitorus/pkcs7, golang-jwt, mattermost/xml-roundtrip-validator) on keyorix's SAML and
backup call paths. The targets call only the libraries, never keyorix code, so a regression
in a pinned library behaviour surfaces here rather than as a silent change under the SSO
flow. The invariants below are the library properties keyorix's security depends on; each
names the fuzz target that fails when the property stops holding.

Format: `INV-LIBCONF-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-LIBCONF-<slug>.md`, one per file.
This package holds differential and conformance fuzz targets that pin the behaviour
Keyorix relies on in third-party parsing / crypto / schema libraries. It has no
non-test code (see `doc.go`): the targets call only the libraries, never Keyorix
code, so the package links a minimal coverage map.

New invariants go in `INVARIANTS.d/INV-LIBCONFORMANCE-<kebab-slug>.md` (one per
file), per the root `CLAUDE.md` convention.

Format: `INV-LIBCONFORMANCE-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.
