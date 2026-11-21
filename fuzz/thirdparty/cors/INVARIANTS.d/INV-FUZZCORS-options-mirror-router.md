- **INV-FUZZCORS-options-mirror-router** `keyorixCORSOptions` in
  `cors_fuzz_test.go` must equal the live `cors.Options` literal in
  `server/http/router.go` field for field (methods, headers, exposed headers,
  MaxAge, AllowCredentials), with only `AllowedOrigins` supplied by the harness
  (router.go derives it from config at runtime). Why: the oracles O-CORS-1..4
  prove properties of the option set the harness builds; a mirror that drifted
  from router.go would keep them green while the real middleware runs a
  different configuration. Guard: `TestCORSOptions_MirrorRouter` (go/ast
  evaluation of router.go's literal, failing on any field it does not mirror),
  red/green-proven in `TestCORSOptions_MirrorRouter_RedGreen`
  (`fuzz/thirdparty/cors`). Does NOT verify `getAllowedOrigins` itself (the
  allowlists are the harness's own; see
  [[INV-FUZZCORS-exact-config-never-reflects-unlisted]]).
