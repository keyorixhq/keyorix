- **INV-FUZZCORS-exact-config-never-reflects-unlisted** Under Keyorix's reachable CORS
  configuration — `getAllowedOrigins` returns an EXACT, wildcard-free, star-free origin
  list (the dev localhost set, or a configured prod list, or the same-origin
  `https://<domain>`) and `AllowCredentials:true` — the go-chi/cors middleware must
  never emit an `Access-Control-Allow-Origin` that is not the request `Origin` AND a
  case-insensitive member of that list, and must never emit `Access-Control-Allow-Origin:*`
  (which cannot arise without a literal `"*"` in the list). Why: a reflected
  non-allowlisted origin with `Access-Control-Allow-Credentials:true` is a
  cross-origin credential-theft bypass; this is the one CORS property that is directly
  attacker-reachable (the `Origin` header is attacker-controlled and `cors.Handler` is
  the first security middleware in `server/http/router.go`). Guard:
  `TestCORSRealConfig_NeverReflectsUnlisted` and `FuzzCORSHostileOrigin` oracle O-CORS-1
  (`fuzz/thirdparty/cors`); the detection logic is red/green-proven in
  `TestCORSOracle_RedGreen`; `TestCORSAllowedOrigins_AreAccepted` proves the harness is
  not vacuously green. Does NOT verify admin-wildcard configs (O-CORS-3 characterises
  those, reachable only via operator misconfiguration), nor Vary/Max-Age/exposed-header
  correctness. Related: [[INV-FUZZCORS-no-credentialed-wildcard]].
