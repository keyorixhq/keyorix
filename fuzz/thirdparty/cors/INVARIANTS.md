# fuzz/thirdparty/cors invariants

Read this before changing the go-chi/cors (`github.com/go-chi/cors`) hostile-origin
harness. This package is test-only (`corshostile`). It pins the CORS behaviour the
live Keyorix request path depends on: `cors.Handler` is the first security-relevant
middleware in `server/http/router.go`, built from `getAllowedOrigins(cfg)`, and the
`Origin` / `Access-Control-Request-*` headers are fully attacker-controlled on every
request. If router.go's `cors.Options` change (methods, headers, credentials), update
`keyorixCORSOptions` in the same change (INV-FUZZCORS-options-mirror-router).

Format: `INV-FUZZCORS-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-FUZZCORS-<kebab-slug>.md` (one per file).

## Oracles
- O-CORS-1 reflect-only-allowlisted (exact config), O-CORS-2 no credentialed wildcard,
  O-CORS-3 matcher pinned to a faithful reference port of cors v1.2.2, O-CORS-4 no
  panic + bounded work (resguard). See the package doc comment and
  `EXPECTED-DIFFERENCE.md` for what each does and does NOT verify.
