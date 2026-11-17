# V5EXT — authzdiff reference-model differential extension

Task V5-EXT / session V5EXT. Branch `fuzz/v5-authz-model-extension`.

**Where the work lives.** The sibling fuzzer session held the one-writer lock on
`/mnt/data/wave7/v5ext/repo` (git-write-guard; SessionStart reported an
ACTIVE-WRITER-LOCK). Per CLAUDE.md's one-writer-per-repo model, a linked worktree
would share that `.git` and the same lock, so write work was done in a SEPARATE
`git clone` at `/mnt/data/wave7/v5ext/repo-wr` (distinct `.git-common-dir` →
exempt from the lock by the guard's own design). The branch ref advances in that
clone; the final commit is on `fuzz/v5-authz-model-extension` there, not pushed.
The report at `/mnt/data/wave7/out/v5ext-REPORT.md` is also committed at
`.scratch/REPORT.md` in the clone.

## Outcome

Three operations bound into the cross-layer authorization differential
(`server/authzdiff`), each red/green validated. **No authorization defect found:**
every bound op's real core / REST / gRPC decision AGREES with the independent
reference model across the whole curated case space. The deliverable is coverage
(HARDENING), not a finding.

| op | route(s) | gate the model checks | core leg |
|---|---|---|---|
| `riskexception.approve` | `POST /api/v1/risk-exceptions/{id}/approve` | `system.write`@global (router) | excluded (core_refusal `none`) |
| `riskexception.delete` | `DELETE /api/v1/risk-exceptions/{id}` | admin role @global (core's creator-or-admin-tier) | **included** (core_refusal `typed`) |
| `breakglass.revoke` | `POST /api/v1/projects/{id}/break-glass/{activationId}/revoke` + `GRPC BreakGlassService.RevokeBreakGlass` | `roles.assign`@project (REST router AND gRPC interceptor) | excluded (core_refusal `none`) |

## Coverage before / after

Computed from the generated `server/authzdiff/COVERAGE-ALL.md` totals row
(regenerated with `AUTHZDIFF_REGEN_COVERAGE=1 go test ./server/authzdiff -run
TestCoverageAllIsCurrent`):

- Before: **REST 93/212, gRPC 35/47**.
- After:  **REST 96/212, gRPC 36/47** (+3 REST routes, +1 gRPC RPC).

The six review families in `COVERAGE.md` are unchanged (these ops are in the
`secrets`/`other` families, not the six).

## Method and validation

Each model rule was derived from the endpoint's documented gate (router
registration in `server/http/router.go`, gRPC interceptor in
`server/grpc/services/break_glass_service.go`, and core's own authorization
checks), independently of reading the decision back from the code under test, then
bound as an `opSpec` and run:

- **Strict sweep** `TestV5extStrictSweep` (always-on, env-free; `go test
  ./server/authzdiff`): 52 cases over every named principal + a curated
  gate-boundary set (holder / non-holder / wrong-scope / via-group / machine) for
  each op. Result: **52 cases, 0 O1/O2 disagreements, 0 uncalibrated.** It drives
  the full `runCase` (all three legs) because `breakglass.revoke` has a real gRPC
  leg.
- **Red/green plants** (`AUTHZDIFF_PLANTS=1`, `plants_test.go`), each drops the
  op's load-bearing gate in an overlay and requires ≥N `unexplained` cases
  planted and **0** on a clean tree:
  - `riskexception-approve-router-gate-removed` → **59** planted / 0 clean.
  - `riskexception-delete-core-gate-removed` (targets core's creator-or-admin
    gate, which is load-bearing; the router's `system.write` is redundant with it)
    → **2** planted / 0 clean.
  - `breakglass-revoke-rest-gate-removed` (drops the REST router gate, keeps the
    gRPC gate → REST over-allows what gRPC + model deny) → **239** planted / 0 clean.
- Full package guard suite (`go test ./server/authzdiff`, no env): **ok**, incl.
  coverage freshness, matrix freshness, partition and waiver guards.

### Why these three, and why the siblings are left unbound

The reference model decides the GATE (scoped permission) only. An op is cleanly
bindable iff the layer that enforces the gate is the one the model models:

- `riskexception.approve` / `breakglass.revoke`: `core_refusal:"none"`, so the
  core leg is excluded (ID-2) and the op is a pure transport-gate differential.
  The core-level business rules that still run on the REST/gRPC legs (approve's
  human-only + creator≠approver; revoke's not-found/already-revoked/last-admin
  guard) never fire for a probed principal given the fixtures: the risk exception
  is created by a NON-probed user (`u-risk-creator`), and the break-glass
  activation is seeded active by a dedicated member (`u-bg`).
- `riskexception.delete`: `core_refusal:"typed"`, BUT the typed refusal is a REAL
  permission gate (creator-or-admin-tier). With a non-probed creator, the
  effective gate for every probed principal is "admin role at global scope" —
  exactly the model's `globalAdminRole` requirement — so the included core leg
  agrees.
- **Left analyzed-not-bound (EXPECTED-DIFFERENCE, documented in
  `ops_v5ext_test.go` and `coverage_reasons_test.go`):** access-review
  `attest` / `decide` / `revoke`, break-glass `review`. Their core rows are
  `core_refusal:"typed"` (so the core leg participates), yet core does NOT
  re-check the router's scoped permission — it enforces only reviewer-
  independence / human-only / grant-exists controls. The core leg would then
  ALLOW a no-permission principal that the router (and the model, which models
  the router permission) denies: a core-leg `O2:allowed-but-model-denies`
  disagreement no existing waiver absorbs. Binding them would require either a
  model that special-cases the core leg or a new waiver — a harness change out of
  scope here. access-review `close` additionally cannot be calibrated: its
  force-close-independence business rule refuses the admin positive control (the
  admin is itself a review subject). Bulk secret ops (`bulk-delete`/`-rename`/
  `-rotate`, `suspend-all`/`resume-all`) authorize PER ITEM in core while the
  REST router carries only a project-wide gate, so core and REST authorize
  different questions — the V5 note already records this and it is unchanged.

### Reachability

The harness drives the REAL router (`httpserver.NewRouter`) and the REAL gRPC
server (`keyorixgrpc.NewServer`) on a production-migrated seeded store, so the
bound routes are reached through their live wiring, not a synthetic call graph.
Reachability to each gate is demonstrated by its admin positive control passing
(an uncalibrated binding fails the strict run): the global admin actually opens
the route, reaches the gate, and is allowed. No claim here depends on an
unreachable path.

### Resource-spike detection

The differential has no new fuzz target; the three ops join the existing
`FuzzAuthzDiff` (registered at `scripts/fuzzing/targets.d/server-authzdiff__FuzzAuthzDiff.conf`),
which drives them automatically because op enumeration is `ops()`. Each fuzz
input runs under `go test`'s own per-run timeout (a hung input trips the test
timeout, surfacing as a FAIL, not a silent spike); each leg clones the template
into an in-memory SQLite image and releases it at case end (`leg.close`), so a
runaway case cannot accumulate unbounded DB copies — the memory ceiling is one
template image per concurrent leg, and `legsCreated`/template-size are logged so a
sweep's cloned bytes are computable without fs tracing. A crash or OOM on a bound
op is caught by the fuzzer; a per-input wall-clock blow-up is caught by the test
timeout.

## What the oracles do NOT verify (standing)

- Oracle 2 vs REST is NOT independent of the route gate string (the model's REST
  requirement is the router gate recorded for the op); it checks scope / expiry /
  machine-no-admin-override / ceiling, not WHICH permission the route names.
  Independent only for the core and gRPC legs.
- For `riskexception.approve` / `breakglass.revoke` the CORE leg is excluded
  (ID-2), so these oracles do not check core's own behaviour — only that the
  transports' gate matches the model. The core business rules are exercised
  indirectly (they run on the transport legs) but not compared.
- The model does NOT model: the SoD-live-violation re-check on approve, the
  break-glass activation state machine / last-admin guard, access-review reviewer-
  independence, ownership/share/ACL beyond documented owner rules, MFA, SCIM,
  time-window schedules, restricted-classification gates.

## Classification of everything surfaced

- **HARDENING** — three new differential bindings + three new red/green plants +
  one new always-on strict guard + one invariant fragment. No production code
  changed.
- **EXPECTED-DIFFERENCE** — the access-review attest/decide/revoke, break-glass
  review, access-review close, and bulk-secret endpoints, left unbound for the
  structural reasons above (recorded in code, not just prose).
- No VULNERABILITY / CANDIDATE / SECURITY-DEFECT / DEFECT found: the real server
  agreed with the independent model on every bound case.

## Files changed (all test-only + docs, no production code)

- `server/authzdiff/ops_v5ext_test.go` (new) — the three bindings.
- `server/authzdiff/sweep_v5ext_test.go` (new) — `TestV5extStrictSweep`.
- `server/authzdiff/ops_test.go` — `ops()` aggregator appends `v5extOps()`.
- `server/authzdiff/world_test.go` — fixtures: `fx.riskExceptionID`,
  `perProject.breakGlassActivationID`, and their seed (`u-risk-creator`, `u-bg`).
- `server/authzdiff/plants_test.go` — three red/green plants.
- `server/authzdiff/COVERAGE-ALL.md` — regenerated (REST 96, gRPC 36).
- `server/authzdiff/INVARIANTS.d/INV-AUTHZDIFF-v5ext-risk-breakglass-gates.md` (new).
- `changelog.d/fuzz-v5-authz-model-extension.md` (new).

## Fuzz run

(updated below after the checkpoint commit — minimum real fuzz time on
`FuzzAuthzDiff` with the new ops integrated.)

## LEFTOVERS

- Bind access-review `attest`/`decide`/`revoke` and break-glass `review` by
  teaching the model a `humanOnly` + reviewer-independence requirement AND
  excluding the core leg where core does not re-gate the router permission (a
  harness change: the coreEnforced flag is matrix-derived `typed`, so the ID-2
  exclusion does not currently apply to them).
- Bind access-review `close` once a fixture provides an independent reviewer so
  the force-close-independence rule does not fail the admin positive control.
- Bind the bulk-secret ops only with a per-item ownership model (they authorize
  per item in core vs a project-wide gate at REST — genuinely different questions).
- SCIM / MFA step-up remain fixture-blocked (SCIM bearer token + IdP-managed
  principal; MFA enrolment state).
