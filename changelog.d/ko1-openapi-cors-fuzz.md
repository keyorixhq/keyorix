### Testing
- Added `fuzz/thirdparty/cors` `FuzzCORSHostileOrigin`: a hostile-origin fuzzer for the
  go-chi/cors middleware as wired in `server/http/router.go`. It drives the real
  `cors.Handler` option set over attacker-controlled `Origin` / `Access-Control-Request-*`
  headers and asserts the reachable CORS security properties — never reflect a
  non-allowlisted origin under the exact allowlist, never pair `Access-Control-Allow-Origin:*`
  with credentials — plus a faithful-reference pin on the origin matcher and a no-panic /
  bounded-work (resguard) oracle. Red/green-proven; committed guard
  `TestCORSRealConfig_NeverReflectsUnlisted`.
- Added `fuzz/thirdparty/kinopenapi` `FuzzOpenAPISchemaBoundedWork`: a bounded-work fuzzer
  for the kin-openapi `openapi3.Schema` validator (deep allOf/anyOf/oneOf nesting, pattern,
  format, additionalProperties, large instances). Oracles: no panic, no hang/amplification
  (`fuzzutil.Guard` + resguard alloc ceiling + superlinear-wall), and schema `MarshalJSON`
  idempotence. Library-hardening (the schema is trusted in every live Keyorix caller).
