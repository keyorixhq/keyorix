# V9 backlog item status: typed error mapper + nightly strict FuzzOpenAPIStateful gate

**Session:** V9GATE (branch `fuzz/v9-nightly-strict-gate`, 2026-11-20)

## What exists today (verified, not assumed)

### FuzzOpenAPIStateful (`server/http/openapi_stateful_fuzz_test.go`)

A schema-driven stateful fuzzer against the full REST API surface. Runs in-process
against the real `NewRouter` stack (chi + auth middleware + handlers + core + crypto +
storage) over a seeded SQLite store. Up to 12 operations per sequence, with id
dependency tracking across calls. 7 oracles — each with its own "does NOT verify"
comment:

| # | Function | Fatal by default? |
|---|----------|-------------------|
| 1 | `osOracleNo5xx` | Only for schema-violating inputs; well-formed → logged unless `KEYORIX_OSF_STRICT=1` |
| 2 | `osOracleConformance` | Yes |
| 3 | `osOracleAuthUnauth` | Yes |
| 4 | `osOracleCanary` | Yes |
| 5 | `osOracleIdempotentRead` | Yes |
| 6 | `osOracleTypedError` | Yes (leak/shape are fatal; undeclared-status and code≠HTTP are non-fatal candidates) |
| 7 | `osOracleDenialExistence` | Yes in strict mode; logged otherwise |

### Oracle 6 (`osOracleTypedError`) — where it runs

**Both** places:

1. **Inside `FuzzOpenAPIStateful`** — called at line 981 of
   `openapi_stateful_fuzz_test.go` on every fuzzer-generated request. This is the
   fuzz corpus path: each input to `FuzzOpenAPIStateful` triggers oracle 6 against the
   responses it generates.

2. **`TestOSFErrorMapperCensus`** (`openapi_error_oracles_fuzz_test.go:322`) — a
   deterministic, non-fuzzing census that drives a fixed set of error-inducing requests
   (bogus id, malformed id, empty/garbage body for writes) across **every** enumerated
   operation. This is the "proving test" that covers the whole API surface regardless of
   where the fuzzer happens to reach.

They are two distinct mechanisms, not duplicates: the census provides deterministic
100%-surface coverage of a narrow probe set; the fuzzer provides stochastic coverage of
deep multi-step interaction sequences the census probes never reach.

### Strict mode

Controlled by `KEYORIX_OSF_STRICT=1` (environment variable, not a build tag, not a
file in the working tree). When set:

- **Oracle 1** becomes fatal for a well-formed request returning an undeclared 5xx
  (not just logged as a candidate).
- **Oracle 7** (`osOracleDenialExistence`) also gates fatally rather than logging.
- Oracles 2-5, 6 are unaffected — they were already always fatal.

The "strict" label in the codebase refers specifically to oracle 1. The comment at
line 1113-1121 of `openapi_stateful_fuzz_test.go` records `OPENAPI-STATEFUL-10`
(`createRotationPolicy` undeclared 500) as "caught by the STRICT fuzz pass itself,
not the sweep — the nightly gate working as intended" — confirming the design intent
is a nightly strict-mode run as the regression gate for oracle 1.

**Default off** because the waiver list (`osKnownUndeclared5xx`) documents 7 real,
unfixed oracle-1 bugs (OPENAPI-STATEFUL-7/1/9/10, all tracked in issue #4132). Without
the waivers, a strict run would halt immediately on the first known defect rather than
exploring for NEW regressions. The waiver mechanism keeps the strict gate live against
new regressions while existing defects are being fixed.

### Known waivers (osKnownUndeclared5xx) as of 2026-11-20

| ID | Operation(s) | Root cause | Fix direction |
|----|--------------|------------|---------------|
| OPENAPI-STATEFUL-7 | `startImpersonation` | Handler switch misses suspended/inactive/ceiling-exceeded/admin-not-found cases → default 500 | 403/409 via better mapping |
| OPENAPI-STATEFUL-1 | `getSecretAuditTrail`, `getSecretOwnershipHistory`, `listAccessors` | Machine principal reaches legacy `default:500` branch instead of `answerCoreError` | Route through `answerCoreError` |
| OPENAPI-STATEFUL-9 | `createSecretTemplate`, `createRejectionReasonTemplate` | DB unique-constraint violation classified `errclass.Internal` → 500 instead of 409 | Add Conflict sentinel in core |
| OPENAPI-STATEFUL-10 | `createRotationPolicy` | Plain `fmt.Errorf` for cross-project/non-existent env → handler misses it → 500 | Wrap in `invalidInput` or `NotFound` |

All tracked under issue #4132. Each waiver has a deterministic reproducer in
`TestOpenAPIStrictExceptions` (`openapi_strict_exceptions_test.go`).

### CI wiring today

**None for FuzzOpenAPIStateful.** Grep of `.github/workflows/` for `FuzzOpenAPIStateful`,
`TestOSFErrorMapper`, `OSF`, `KEYORIX_OSF_STRICT` returns zero matches. The fuzz target
runs only:
- manually (developer invocation)
- on the continuous rig (`scripts/fuzzing/`) when it reaches this target in rotation

The existing nightly schedules are:
- `ci.yml` — 06:17 UTC (runs `go test ./server/http/...` which includes the seed corpus
  replay, but NOT `-fuzz` mode and NOT `KEYORIX_OSF_STRICT=1`)
- `dast.yml` — 06:43 UTC (black-box Nuclei scan, unrelated)
- `guard-nightly.yml` — 07:53 UTC (guard expiry/rollout, unrelated)
- `pg-race-tests.yml` — 08:27 UTC (Postgres cross-replica races, unrelated)
- `fault-tolerance-nightly.yml` — 07:29 UTC (fault-injection issue state, unrelated)
- others: e2e-nightly, govulncheck, trivy, sonarcloud, docker-publish, etc.

**A "nightly strict gate" for FuzzOpenAPIStateful does not exist.** The backlog item
calling it "not verified" is accurate. The comment at line 1114 of
`openapi_stateful_fuzz_test.go` ("nightly gate working as intended") is describing
the DESIGN INTENT, confirmed by a manual run, not a wired CI job.

## What was run in this session

### `TestOSFErrorMapperCensus` and `TestOSFDenialExistenceCensus`

Run: `go test -run 'TestOSFErrorMapperCensus|TestOSFDenialExistenceCensus' -v -count=1 ./server/http/`

Result: **PASS** (both)

Census report (from test log):
- ERROR-MAPPER CENSUS over **310 operations**, **956 error responses** probed
- Leaks (stack/path/sql/secret): **0**
- JSON error bodies missing `error` label: **0**; missing `code`: **0**
- Distinct non-JSON/empty error (op,status): **0**
- Distinct undeclared non-2xx (op,status): **147** (non-fatal candidates — many 4xx are legitimately undeclared)
- Distinct code≠status (op,status): **0**
- DENIAL-EXISTENCE CENSUS: **102** (op,principal) denial pairs checked, **0** differ

### `FuzzOpenAPIStateful` in strict mode

Run (3 × 60s foreground chunks, `KEYORIX_OSF_STRICT=1 GOMAXPROCS=2`, SQLite backend):

| Chunk | Executions | New interesting | Result |
|-------|------------|-----------------|--------|
| 1 | 7,732 | 25 | **PASS** |
| 2 | 22,703 | 104 | **PASS** |
| 3 | 12,884 | 54 | **PASS** |

All three chunks exited 0 with no oracle violations. The existing waivers
(`osKnownUndeclared5xx`) correctly suppressed the 7 known defects (OPENAPI-STATEFUL-
7/1/9/10); no new undeclared-5xx regressions were found across ~43k executions.

Oracles 2-5 (conformance, authz, canary, idempotent-read) and oracles 6-7 (typed
error mapper, denial existence independence) all ran against every generated request
with no fatal findings.

The seed corpus for `FuzzOpenAPIStateful` has 12 built-in entries (reported by the
fuzzer's baseline phase); no entries are committed to `testdata/fuzz/FuzzOpenAPIStateful/`.

## The gap and what was built

**Gap:** No CI workflow wires `FuzzOpenAPIStateful` with `KEYORIX_OSF_STRICT=1` on any
schedule. The intent ("nightly strict gate") is stated in the code's own comment but was
never realized as a `.github/workflows/` file.

**Built:**
- `docs/fuzzing/v9-nightly-strict-gate.workflow.yml.proposed` — a proposed workflow
  file (NOT under `.github/workflows/`; not enabled). Contains the full YAML, a
  runner-minute cost estimate (~8-10 min/night), scheduling rationale (nightly cron at
  09:43 UTC, not merge queue), and an explicit "does NOT verify" section.

## What the typed-error-mapper oracle does NOT verify

(From the oracle's own comment; reproduced here because CLAUDE.md requires asking this
of every mechanism.)

- **`message` text**: only that it is not a leak pattern, not that it matches the
  documented sentence.
- **`code` field value**: recorded as a mismatch candidate, not gated — a handler may
  legitimately carry an application-level code that differs from the HTTP status.
- **Non-JSON or empty error bodies**: recorded as a candidate (INV-HTTP-error-responses-
  uniform says they should not occur), but net/http's own pre-handler 400/431 responses
  are out of scope.
- **Leakage through encoding/transformation**: the oracle uses literal substring
  patterns. A stack trace base64-encoded into a JSON field, or a SQL error embedded in
  a translated message string, would not be caught.
- **Status code correctness**: undeclared non-2xx statuses are enumerated but non-fatal.
  Whether a 403 is the semantically correct response vs a 404 is not verified.
- **Empty corpus gap**: with no committed seed corpus for this target, a short fuzz run
  explores from randomly generated inputs. The census (`TestOSFErrorMapperCensus`) is
  the mechanism that actually covers the whole API surface; the fuzzer samples it.

## Leftovers

- TODO-ISSUE: wire `docs/fuzzing/v9-nightly-strict-gate.workflow.yml.proposed` into
  `.github/workflows/` once the maintainer decides the runner-minute budget is
  acceptable. The proposed slot (09:43 UTC) does not conflict with any existing workflow.
- TODO-ISSUE: add a seed corpus for `FuzzOpenAPIStateful` (at least one committed entry
  per operation group) so the strict-gate run starts from a known-good corpus baseline
  rather than from scratch. Without a committed corpus, a nightly run that finds nothing
  is consistent with both "working" and "not reaching anything interesting."
- TODO-ISSUE: resolve issue #4132 (OPENAPI-STATEFUL-1/7/9/10) — until those waivers
  are removed from `osKnownUndeclared5xx`, strict mode cannot catch a NEW defect on the
  same operations they waive.
