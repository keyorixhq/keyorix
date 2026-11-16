# KO1 — kin-openapi / go-chi (chi + cors) hostile-request fuzzing

**Report location note.** `/mnt/data/wave4/out/` is not writable from this sandbox
(writes outside the working tree are blocked). Per the runtime fallback rule this
report lives at `.scratch/ko1-REPORT.md`, committed on the branch
`fuzz/ko1-openapi-validator-and-router`.

**Temperature note.** `/sys/class/hwmon/hwmon2/temp1_input` is not readable from this
sandbox (path outside the working directory is blocked even read-only). All runs use
`nice -n 10`, `GOMAXPROCS=2`, `-parallel 2` as the thermal safeguard instead.

**Most-reasonable-reading statement.** The task asks to drive the REAL router and
validator with hostile requests. On inspection the repo already has strong coverage of
two of the three requested surfaces (see "Existing coverage" below): the chi router
vs authz differential and the kin-openapi stateful request/response fuzzer are both
mature. The genuine, un-covered gaps are (1) **go-chi/cors** (only an env-label config
test exists; no hostile-origin / preflight / credentialed-wildcard fuzzing) and (2) a
**kin-openapi schema bounded-work** angle (the one existing kin-openapi differential
fuzzer uses three tiny hand-written schemas with no `pattern`/`format`/composition and
NO resource metering — exactly the ReDoS/schema-explosion surface the task flags as the
likely real find). I therefore build two NEW targets that extend, not duplicate, the
existing set, and I do NOT rebuild the chi-routing differential (already covered by
`server/middleware/FuzzChiAuthzRouteDifferential`) or the stateful OpenAPI request
fuzzer (`server/http/FuzzOpenAPIStateful`).

---

## Status (live)

- [x] Orientation, existing-coverage inventory, library source review (cors, chi, kin)
- [ ] Target 1 — `fuzz/thirdparty/cors` `FuzzCORSHostileOrigin` built + red/green
- [ ] Target 1 — 4× 540 s fuzz chunks
- [ ] Target 2 — `fuzz/thirdparty/kinopenapi` schema bounded-work built + red/green
- [ ] Target 2 — 4× 540 s fuzz chunks
- [ ] targets.d registration, INVARIANTS fragments, changelog fragments
- [ ] Final classification + commit

---

## Existing coverage (verified, NOT rebuilt)

| Surface | Existing target | What it owns |
|---|---|---|
| chi routing vs authz | `server/middleware` `FuzzChiAuthzRouteDifferential` + `TestChiAuthzRouteDifferential_{Seeds,RedProof}` | path encodings (%2f, dot-seg, double-slash, trailing, case, unicode), route→authz consistency, routing differential vs reference matcher; CH1-A/B/C oracles, red/green proven |
| kin-openapi request/response on REAL router | `server/http` `FuzzOpenAPIStateful` (+ swarm, error oracles) | stateful sequences against real `NewRouter` chi stack; 5xx, response conformance, unauth authz, canary, idempotent reads |
| kin vs santhosh schema verdicts | `internal/libconformance` `FuzzJSONSchemaValidatorDifferential` | verdict differential on 3 tiny schemas (pat-create, role-enum, string-array); no pattern/format/composition, no resource metering |
| CORS config | `server/http` `TestEnvironmentLabel_TemplatesDoNotRelaxCORS` | only: env label picks localhost vs configured origins |

**Gaps this task fills:** go-chi/cors hostile-origin + preflight + credentialed-wildcard
behaviour (reachable: `cors.Handler` is a live middleware in `server/http/router.go`,
Origin is fully attacker-controlled); kin-openapi schema validation *bounded work*
(ReDoS / composition explosion / recursive refs / deep nesting) which no existing
target meters.

---

## Library facts established (source-reviewed)

### go-chi/cors v1.2.2 (`cors.go`, `utils.go`)
- Origin match (`isOriginAllowed`): exact case-insensitive membership in `allowedOrigins`
  (lower-cased at `New`), OR wildcard prefix/suffix via `wildcard.match` =
  `len(s)>=len(prefix+suffix) && HasPrefix && HasSuffix` (pure string, no URL parse).
- `allowedOriginsAll` set when list contains `"*"`; then ACAO is literally `"*"`.
- When NOT all-origins, ACAO is set to the **original-case** request `Origin` value
  (not the lowered one) — line 270/321.
- `AllowCredentials` ⇒ `Access-Control-Allow-Credentials: true` added whenever the
  origin was allowed. Keyorix sets `AllowCredentials: true`.
- Preflight gate: `OPTIONS` + non-empty `Access-Control-Request-Method` + Origin header
  present. Vary headers always added on preflight.
- Keyorix `getAllowedOrigins`: dev ⇒ fixed localhost set; prod ⇒ configured
  `AllowedOrigins` list, else `https://<domain>` (same-origin). No `"*"` is ever
  produced by Keyorix itself; a wildcard pattern only appears if an admin puts one in
  `server.http.allowed_origins`.

### kin-openapi v0.153.0
- Go `regexp` (RE2) backs `pattern` ⇒ no classic catastrophic ReDoS; plausible blow-up
  is composition explosion (allOf/anyOf/oneOf), recursive `$ref`, deep nesting, huge
  arrays, format validators. Measured with resguard + a wall watchdog.

### go-chi/chi v5.5.0
- Routing differential already owned by `FuzzChiAuthzRouteDifferential`; not rebuilt.

---

## Targets (detail filled as built)

### Target 1 — `fuzz/thirdparty/cors` `FuzzCORSHostileOrigin`
(meters, oracles, red/green, runs, findings — TBD)

### Target 2 — `fuzz/thirdparty/kinopenapi` schema bounded-work
(meters, oracles, red/green, runs, findings — TBD)

---

## What each oracle does NOT verify
(TBD per target)

## Findings
(TBD)

## LEFTOVERS (ranked, with suggested vCD minutes)
(TBD)
