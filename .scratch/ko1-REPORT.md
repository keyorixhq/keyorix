# KO1 — kin-openapi / go-chi (chi + cors) hostile-request fuzzing

**Report location.** `/mnt/data/wave4/out/` is not writable from this sandbox (writes
outside the working tree are blocked). Per the runtime fallback rule this report lives
at `.scratch/ko1-REPORT.md`, committed on branch `fuzz/ko1-openapi-validator-and-router`
with `git add -f` (`.scratch` is gitignored).

**Temperature.** `/sys/class/hwmon/hwmon2/temp1_input` is not readable from this sandbox
(path outside the working dir is blocked even read-only). Thermal safeguard was instead
`nice -n 10`, `GOMAXPROCS=2`, `-parallel 2` on every build and fuzz run.

**Most-reasonable-reading (stated, no questions asked).** The repo ALREADY has mature
coverage of two of the three requested surfaces: the chi router↔authz differential
(`server/middleware FuzzChiAuthzRouteDifferential`, with percent/encoded-slash/dot-seg/
double-slash/trailing/case/unicode seeds and a reference-matcher differential) and the
kin-openapi request/response stateful fuzzer against the real `NewRouter` chi stack
(`server/http FuzzOpenAPIStateful`). Rebuilding those would duplicate, which the task
forbids. The two genuine GAPS — and what I built — are:
1. **go-chi/cors** had no hostile-input test at all (only `TestEnvironmentLabel_
   TemplatesDoNotRelaxCORS`, a config-template check that never exercises the middleware).
2. **kin-openapi schema BOUNDED WORK** (ReDoS / composition-explosion / recursion /
   round-trip) was unmetered: the one existing kin fuzzer
   (`internal/libconformance FuzzJSONSchemaValidatorDifferential`) compares verdicts on
   three tiny fixed schemas with no `pattern`/`format`/composition and no resource meter.

Both new targets drive the REAL library code and use the shared `resguard` resource
helper. I did NOT touch production code.

---

## Deliverables (committed: c12260b4b6, protective commit before fuzzing)

| Target | Package | Fuzz func | Registered | Budget |
|---|---|---|---|---|
| CORS hostile-origin | `fuzz/thirdparty/cors` (`corshostile`) | `FuzzCORSHostileOrigin` | `targets.d/fuzz-thirdparty-cors__*.conf` + regenerated `targets.conf` | `testdata/resguard-cors.json` |
| kin-openapi bounded-work | `fuzz/thirdparty/kinopenapi` (`kinhostile`) | `FuzzOpenAPISchemaBoundedWork` | `targets.d/fuzz-thirdparty-kinopenapi__*.conf` | `testdata/resguard-kinopenapi.json` |

Also: `INVARIANTS.md` + `INVARIANTS.d` fragments for both (`INV-FUZZCORS-*`,
`INV-FUZZKIN-*`), index rows in `docs/INVARIANTS.md` (incl. the pre-existing missing
`internal/fuzzutil/resguard` row, fixed in passing), `fuzz/thirdparty/cors/
EXPECTED-DIFFERENCE.md`, and `changelog.d/ko1-openapi-cors-fuzz.md`.

---

## Result summary

**No findings (no VULNERABILITY / CANDIDATE / DEFECT).** Both targets ran 4×540 s
foreground chunks (`GOMAXPROCS=2`, `-parallel 2`, `nice -n 10`), all green, no crashers
saved. The CORS run is a **confirmed-good NEGATIVE**: the reachable CORS security
properties hold under ~9.1M executions. The kin run is a **library-robustness NEGATIVE**:
no panic, no >2.5 s single-input work, no alloc-ceiling breach, no round-trip drift over
~6.6M executions.

| Target | Chunks | Exec total (approx) | Corpus end | Crashers | Verdict |
|---|---|---|---|---|---|
| `FuzzCORSHostileOrigin` | 4×540 s | ~9.14M (2.07M/2.19M/2.28M/2.54M) | 271 | 0 | PASS — reachable CORS props hold |
| `FuzzOpenAPISchemaBoundedWork` | 4×540 s | ~6.58M (1.84M/2.01M/1.23M/1.50M) | 946 | 0 | PASS — library robust in-bounds |

Total measured fuzz wall time: 8 × ~541 s ≈ **72 min**. (Pre-run smoke runs, not counted.)

---

## Existing coverage (verified, deliberately NOT rebuilt)

- `server/middleware FuzzChiAuthzRouteDifferential` + `TestChiAuthzRouteDifferential_
  {Seeds,RedProof}` — chi routing vs authz; CH1-A/B/C oracles; a reference matcher and an
  `EXPECTED-DIFFERENCE` table covering encoded-slash, percent-encoding, double-slash,
  dot-segment, trailing-slash, reference-ambiguous. Red/green-proven.
- `server/http FuzzOpenAPIStateful` (+ swarm + error oracles) — kin-openapi spec load +
  stateful request sequences against the real chi stack; oracles for undeclared-5xx,
  response conformance (`openapi3filter.ValidateResponse`), unauth authz, canary,
  idempotent reads.
- `internal/libconformance FuzzJSONSchemaValidatorDifferential` — kin `Schema.VisitJSON`
  vs santhosh verdict differential on 3 tiny schemas; no pattern/format/composition, no
  metering.
- `server/http TestEnvironmentLabel_TemplatesDoNotRelaxCORS` — CORS config template only.

---

## Target 1 — `FuzzCORSHostileOrigin` (go-chi/cors v1.2.2)

**Reachability (traced to a live caller).** `cors.Handler(cors.Options{…})` is installed
in `server/http/router.go` as the first security-relevant middleware, built from
`getAllowedOrigins(cfg)`. The `Origin` and `Access-Control-Request-*` headers are fully
attacker-controlled on every request. This target reproduces router.go's EXACT option set
(`keyorixCORSOptions`) and runs two configs: the reachable EXACT allowlist (dev localhost
set ∪ a prod same-origin), and a wildcard allowlist (reachable only if an operator puts a
`*`-pattern in `server.http.allowed_origins`).

**Meters enabled (resguard) and why.** `alloc_bytes` + `mallocs` (FATAL, input-
attributable): a CORS serve's only input-scaled allocation is `parseHeaderList`'s
`make([]string, 0, commaCount)` on a comma-dense `Access-Control-Request-Headers`, so an
amplification there is exactly what these catch. `wall_ns`/`cpu_ns` advisory (process
noise). `live_heap` DROPPED from the budget (`INV-FUZZCORS-liveheap-not-metered`): a
sub-microsecond serve's post-GC whole-process heap reading is the fuzz engine's heap, not
input work — it false-tripped at 1.4× on a 7-byte input during the first smoke run; drift
leaks would still surface via `Probe.CheckDrift`. No disk/net/sleep/DB meters (the
middleware uses none). Budget calibrated on 36 benign serves incl. a comma-dense header.

**Oracles.**
- **O-CORS-1 (FATAL, reachable security):** under the EXACT allowlist, any emitted
  `Access-Control-Allow-Origin` must equal the request `Origin` AND be a case-insensitive
  member of the allowlist; `*` is impossible here. Catches reflection of a non-allowlisted
  origin (credential-theft bypass).
- **O-CORS-2 (FATAL, reachable security):** `ACAO:*` and `Access-Control-Allow-Credentials:
  true` must never co-occur (the classic credentialed-wildcard bypass).
- **O-CORS-3 (FATAL):** go-chi's origin verdict (observed via a canonical preflight that
  isolates the origin gate) must equal a line-for-line reference port of cors v1.2.2's
  `isOriginAllowed` + `wildcard.match`. Pins the matcher against a dependency-bump change.
- **O-CORS-4 (FATAL):** no panic; serve metered against the calibrated budget.

**Red/green proofs (committed).** `TestCORSOracle_RedGreen` (O-CORS-1/2 fire on a crafted
reflected-evil-origin / credentialed-wildcard response, pass on benign);
`TestCORSDifferential_RedGreen` (O-CORS-3 comparison distinguishes a matcher change);
`TestCORSRealConfig_NeverReflectsUnlisted` (committed guard: 12 hostile origins × 4 request
shapes, never reflected); `TestCORSAllowedOrigins_AreAccepted` (non-vacuity: a legit origin
IS reflected with credentials).

**What O-CORS-* does NOT verify.**
- Not the wildcard-config security posture: O-CORS-1/2 assert only under the EXACT
  (reachable) allowlist. The wildcard config is characterised by O-CORS-3 (pins go-chi's
  documented prefix/suffix string matching) but no claim is made that an operator's
  `*`-pattern is "safe" — a `*keyorix.example` (no dot) footgun is out of scope and noted
  in `EXPECTED-DIFFERENCE.md`.
- Not `Vary`, `Access-Control-Max-Age`, or the exposed-header list correctness.
- Not browser enforcement semantics (whether a browser would honour a given header) — it
  asserts on the raw response headers only.
- Not CORS interaction with auth/routing further down the chain (the next handler here is a
  sentinel; routing+authz are owned by the chi differential target).
- Case-folding (`Origin: HTTP://LOCALHOST:3000` matching `http://localhost:3000`) is
  documented EXPECTED, not a finding (go-chi lower-cases both sides by design; the reflected
  value still equals the request Origin, so it is only relevant if the attacker page already
  runs at that origin).

---

## Target 2 — `FuzzOpenAPISchemaBoundedWork` (kin-openapi v0.153.0 `openapi3`)

**Reachability (traced, and honestly bounded).** kin-openapi `Schema` validation is reached
by Keyorix in `server/http/handlers/contracttest` (test-only), the `server/http` OpenAPI
stateful fuzzer (test-only, validates handler RESPONSES against the trusted spec) and
`internal/egressguard`. In EVERY live caller the SCHEMA is the trusted committed
`openapi.yaml` and the INSTANCE is a handler's own response or a test body — **never a raw
attacker-controlled schema+instance pair.** So any finding here is a LIBRARY property,
classified HARDENING/CANDIDATE and **labelled not attacker-reachable**. The target exists to
catch a dependency-bump regression in the robustness Keyorix's trusted callers assume
(a recursion panic, an amplification, or a serialization drift would silently weaken them).
kin's `pattern` uses Go `regexp` (RE2) — **no classic catastrophic ReDoS is possible** — so
the plausible blow-up was composition explosion / deep recursion, which is what the target
drives.

**Meters enabled and why.** `fuzzutil.Guard` (3 s hang/amplification watchdog, FATAL) wraps
the WHOLE per-input body (decode + `VisitJSON` + round-trip) so a slow stage is attributed,
not absorbed into a stalled worker. `resguard` `alloc_bytes`+`mallocs` (FATAL) meter
`VisitJSON` against a calibrated ceiling (composition explosion allocates error structures).
`live_heap` dropped for the same reason as CORS (`INV-FUZZKIN-liveheap-not-metered`).
O-KIN-2b adds a direct 2.5 s superlinear-wall ceiling (below Guard's 3 s) so a near-threshold
slow input is saved WITH its input sizes. Input bounded to 8 KiB schema + 8 KiB instance
(larger inputs mainly stall the fuzz engine's own corpus I/O without reaching new behaviour).

**Oracles.** O-KIN-1 no panic (native); O-KIN-2 bounded work (Guard + resguard +
O-KIN-2b wall); O-KIN-3 schema `MarshalJSON`→`UnmarshalJSON`→`MarshalJSON` idempotence.

**Red/green proofs (committed).** `TestKinOracles_RedGreen` (O-KIN-3 comparison red/green;
O-KIN-2 budget fires on a crafted 1 GiB alloc cost, passes benign); `TestKinSeeds_
NoPanicRoundTrip` (deterministic replay of all seeds incl. 64-deep allOf, nested-object,
anyOf-explosion, large-array); `TestKinHarness_NotVacuous` (VisitJSON actually discriminates
valid from invalid, so a green run is meaningful).

**What O-KIN-* does NOT verify.**
- Nothing with an attacker-controlled SCHEMA (no such live path exists; this is the whole
  reachability caveat).
- Not semantic schema equality — only kin's own marshal fixed point (a reorder-but-equivalent
  schema is not flagged).
- Not cross-document `$ref` resolution (standalone-schema decode does not resolve refs; a
  recursive-ref blow-up during full-document `LoadFromData` is a LEFTOVER, below).
- Not `format`-assertion correctness (default `VisitJSON` does not enforce formats unless a
  format checker is registered — Keyorix does not register custom ones here).
- Not behaviour above 8 KiB inputs, and not a true superlinear bug slower than ~2.5 s that
  only appears at larger sizes.
- The engine's `0/sec` stalls observed during runs are the Go fuzzing engine minimising large
  corpus entries under `GOMAXPROCS=2` (confirmed: at an 800 ms ceiling nothing fired and no
  crasher saved, i.e. no single guarded input exceeds even 800 ms) — an ARTIFACT, not a
  per-input library cost.

---

## Findings

**None.** Classified honestly:
- CORS: **EXPECTED / confirmed-good.** The reachable security invariants
  (`INV-FUZZCORS-exact-config-never-reflects-unlisted`, `-no-credentialed-wildcard`) hold.
  go-chi's case-insensitive matching and pure-string wildcard matching are documented,
  intended behaviours (see `EXPECTED-DIFFERENCE.md`), not defects, and are not reachable as
  a bypass under Keyorix's exact, star-free, wildcard-free config.
- kin-openapi: **no library defect observed in-bounds.** No panic, no amplification, no
  round-trip drift. RE2 rules out `pattern` ReDoS; composition/recursion to the tested
  depths stayed bounded.

No production change is proposed.

---

## Pre-existing issues noted (NOT introduced by this work)

- `internal/statemap TestInvariantDocs_RealRepo` is red on legacy duplicate IDs
  (`INV-CORE-41` ×5, `INV-CORE-42` ×3, `INV-STORE-21` ×4 — all "not failing until migration")
  and on `internal/fuzzutil/resguard/INVARIANTS.md` lacking a `Format:` line. None of these
  files are in this changeset. I DID add the missing `docs/INVARIANTS.md` index row for
  resguard (the index test `TestInvariantDocs_IndexListsEveryFragmentArea` now passes).

---

## LEFTOVERS (ranked; suggested minutes on the vCD hosts)

1. **kin-openapi full-document loader with recursive `$ref` (`openapi3.NewLoader().
   LoadFromData` + `doc.Validate`) — 240 min.** The highest-value untested kin surface: this
   target decodes STANDALONE schemas (no ref resolution). A hostile multi-document spec with
   self/mutually-recursive `$ref`, deep `allOf` chains across refs, or many external refs is
   where a loader stack-overflow or amplification would live. Still library-hardening
   (Keyorix loads only the trusted `openapi.yaml`), so label not-reachable — but it is the
   natural next fuzzer. Wrap `LoadFromData`+`Validate` in `fuzzutil.Guard` + resguard.
2. **go-chi/cors `AllowOriginFunc` / wildcard-config security model — 60 min.** Decide
   whether an operator-set `*`-pattern in `allowed_origins` should be constrained (reject
   patterns without a leading `.`/scheme) at config-validation time, and add a config guard;
   then fuzz that validation. This converts the O-CORS-3 "characterisation" into a reachable
   property. Likely a HARDENING proposal for `internal/config`.
3. **kin-openapi `format` assertions with a registered checker — 60 min.** If Keyorix ever
   registers a custom format validator (e.g. a regex-based one), re-run `FuzzOpenAPISchema
   BoundedWork` with it enabled; a user-supplied Go-regexp format pattern is the one place a
   non-RE2 engine could be introduced. Currently none registered → low priority.
4. **CORS under the real full middleware chain (not a sentinel next-handler) — 90 min.**
   Build the real `NewRouter` and assert CORS headers on 4xx/5xx and on
   routing-rejected requests (does an error response still carry correct/leaky CORS
   headers?). Overlaps the stateful fuzzer; scope carefully to avoid duplication.
5. **kin-openapi `Schema.Validate(ctx)` (schema self-validation) bounded work — 45 min.**
   This target exercises `VisitJSON` (instance validation); `Validate` (schema structural
   validation) is a different code path with its own recursion over composition — worth a
   short separate metered pass.
6. **Larger-input kin pass with corpus reset and `GOMAXPROCS=4` — 60 min.** The 8 KiB bound
   and GOMAXPROCS=2 were chosen for this shared host; a dedicated host could lift both and
   re-check for a superlinear bug that only appears above 8 KiB, clearing the corpus first to
   avoid the engine-minimisation stalls.

---

## Reproduce

```
cd /mnt/data/wave4/ko1
env GOCACHE=/mnt/data/wave4/gocache GOMODCACHE=/mnt/data/wave4/gomod TMPDIR=/mnt/data/wave4/tmp \
  GOFLAGS= GOMAXPROCS=2 nice -n 10 go test ./fuzz/thirdparty/cors/ -count=1          # committed guards + red/green
env ... go test ./fuzz/thirdparty/cors/ -run '^$' -fuzz '^FuzzCORSHostileOrigin$' -fuzztime 540s -parallel 2
env ... RESGUARD_CALIBRATE=1 go test ./fuzz/thirdparty/cors/ -run TestCORSCalibrate   # regenerate the budget
env ... go test ./fuzz/thirdparty/kinopenapi/ -count=1
env ... go test ./fuzz/thirdparty/kinopenapi/ -run '^$' -fuzz '^FuzzOpenAPISchemaBoundedWork$' -fuzztime 540s -parallel 2
```
