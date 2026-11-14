# fuzz/thirdparty/jwt invariants

Read this before changing the golang-jwt/jwt/v5 differential + alg-confusion fuzz
harness. This package is test-only (`jwthostile`, imported from nothing); it mirrors —
and pins — the way the two LIVE Keyorix JWT verification paths configure the parser:
`internal/oidcverify/oidc.go:152` (machine-token / OIDC federation) and
`internal/core/sso.go:1391` (SSO human login). If you change those callers' parser
options, update the mirror here in the same change, or the oracle silently stops
reflecting production.

Format: `INV-FUZZJWT-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-FUZZJWT-<kebab-slug>.md` (one per file).

## Oracles
