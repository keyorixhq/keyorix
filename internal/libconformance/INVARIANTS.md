# internal/libconformance invariants

Read this before changing anything in `internal/libconformance`. This package holds
fuzz targets that PIN the behaviour Keyorix relies on in third-party parsing/crypto
libraries (etree, crewjam/saml xmlenc, digitorus/pkcs7, golang-jwt, and — added by
BC1 — fxamacker/cbor/v2, google/go-tpm, go-webauthn COSE). The targets call ONLY the
libraries plus `internal/fuzzutil`; they contain no Keyorix production code to move.
Their job is to catch a REGRESSION in a pinned dependency (a future bump that removes
a bound or reintroduces a panic) before it reaches the live Keyorix caller.

Format: `INV-LIBCONFORMANCE-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.
Slug IDs (`INV-LIBCONFORMANCE-<kebab-slug>`) belong in `INVARIANTS.d/` fragments.

New invariants go in `INVARIANTS.d/INV-LIBCONFORMANCE-<slug>.md`, one per file.
