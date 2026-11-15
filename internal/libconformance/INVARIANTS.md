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

New invariants go in `INVARIANTS.d/INV-LIBCONF-<kebab-slug>.md`, one per file, per the
root `CLAUDE.md` convention. The package links a minimal coverage map because the targets
call only the libraries, never Keyorix code. It also holds the differential and
conformance fuzz targets over sibling parsing / schema libraries.

The DF1 cross-library parser-differential targets live here: each feeds ONE input to two
independent library readings and fails on a disagreement that is not on an
EXPECTED-DIFFERENCE allowlist (reason per entry), with a companion dead-entry test so a
stale allowlist row cannot hide a regression.
