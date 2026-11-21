- **INV-FUZZCORS-no-credentialed-wildcard** The go-chi/cors middleware, as Keyorix
  configures it, must never emit `Access-Control-Allow-Origin: *` together with
  `Access-Control-Allow-Credentials: true` in one response. Why: a browser ignores a
  credentialed wildcard, but a non-browser client or a permissive gateway that honours
  it would let any origin read authenticated responses; go-chi only emits `*` when the
  configured allowlist literally contains `"*"` (`allowedOriginsAll`), which Keyorix's
  `getAllowedOrigins` never produces — this pins that it stays that way across a
  dependency bump or a config-template change. Guard: `FuzzCORSHostileOrigin` oracle
  O-CORS-2 and `TestCORSRealConfig_NeverReflectsUnlisted` (`fuzz/thirdparty/cors`),
  red/green-proven in `TestCORSOracle_RedGreen`. Does NOT verify the reverse (a specific
  origin WITH credentials is the intended, safe behaviour and is allowed).
  Related: [[INV-FUZZCORS-exact-config-never-reflects-unlisted]].
