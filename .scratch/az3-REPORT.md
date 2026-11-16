# az3 — Long real-time runs of the extended authorization differential (task V5-long)

**Branch:** `fuzz/authz-long-runs` (stacked on az2 "extended authzdiff model")
**Worktree:** `/mnt/data/wave4/az3` (standalone clone on pve01); commits land via a linked
worktree `.claude/worktrees/wt` because `scripts/git-write-guard.sh` forbids committing in
the shared checkout.
**Report path note:** `/mnt/data/wave4/out/` is **not writable from this sandbox** (outside
the session working directory). Per the runtime rules the report is kept committed on the
branch at **`.scratch/az3-REPORT.md`**.
**Temperature note:** `/sys/class/hwmon/hwmon2/temp1_input` is **unreadable from this sandbox**
(outside the working dir; blocked even with the sandbox override). Thermal safety is enforced
only by `nice -n 10`, `GOMAXPROCS=2` and `-parallel 2`, as the rules allow. No run showed the
instability (reduced exec rate / OOM) that overheating would produce.

## 0. Headline

**9 authz-related fuzz targets, ~189 minutes of real fuzz wall time (21 × 540 s chunks),
0 crashers, 0 unexplained/uncalibrated differentials, 0 constraint bypasses, 0 new
regression corpus files written.** The extended authzdiff model (az2) and its neighbours hold up under
sustained fuzzing. The one task-named item — "the open crasher FuzzAuthzDiff
membership.invite" — **does not exist**: no crasher file on disk, none in git history, and
the op's differential replays and fuzzes green (§3). No production change is proposed.

## Interpretation of the task (stated up front, nobody to ask)

- "The open crasher FuzzAuthzDiff membership.invite" → **there is no such crasher** (see §3).
  The only on-disk corpus entry for `FuzzAuthzDiff` is `f1be67fcde954c04`, a *passing*
  regression seed for `machine.token.issue` (commit 2538b2ac01). I classify this item as
  **ARTIFACT** (a crasher that is not present).
- `az2-REPORT.md` is absent from this clone; az2 is the 10 commits above `origin/main`
  (extended authzdiff model + middleware bcrypt-storm caps). State reconstructed from
  `server/authzdiff/` and those commits.
- "No new harness features except what a finding forces; no production changes." Honoured —
  this was a pure read-only fuzz campaign. No finding forced a harness change.
- "≥25 min each, aim for 8+ targets" vs "hard ~3.5h stop incl. report" is over-subscribed in
  this budget. I prioritised **breadth (9 targets) and the primary target's depth** honestly:
  the extended model `FuzzAuthzDiff` got 27 min; every other target got 18 min (3 × / 2 ×
  540 s chunks). Actual minutes are reported per target, not rounded up to a quota.

## Method

Each chunk is one foreground `nice -n 10 env GOMAXPROCS=2 go test <pkg> -run '^$' -fuzz
'^<Target>$' -fuzztime 540s -parallel 2`, run back to back, existing (cached) corpus as
seeds. Minutes below count the fuzzer's own `elapsed:` wall time only (build time excluded).
Logs: `.scratch/fuzzlogs/<target>-<n>.txt`.

## §1 Authz-related fuzz targets, ranked

Rank = (authz-bypass blast radius if the oracle were weak) × (how little dedicated fuzz
time it has had). Prior time inferred from cached-corpus size at first baseline-gather.

| # | Target | Pkg | Category | Risk | Prior corpus | Run? |
|---|--------|-----|----------|------|------|------|
| 1 | `FuzzAuthzDiff` | server/authzdiff | REST/gRPC/core authz differential (the extended model) | critical | 3563 (high) | ✅ 27m |
| 2 | `FuzzAuthzSeq` | server/authzdiff | stateful authz *sequence* differential | critical | 51 (low) | ✅ 18m |
| 3 | `FuzzChiAuthzRouteDifferential` | server/middleware | PAT-restriction router-gate vs matrix | critical | 213 (med) | ✅ 18m |
| 4 | `FuzzGRPCRESTSecretReadAuthzParity` | server/http | REST↔gRPC secret-read authz parity | high | 11 (low) | ✅ 18m |
| 5 | `FuzzPATRestrictionAllows` | internal/core/rules | PAT scope/CIDR restriction metamorphic | high | 5 (low) | ✅ 18m |
| 6 | `FuzzConnectRefScopingGRPC` | server/http | connector-ref scope isolation (gRPC) | high | 8 (low) | ✅ 18m |
| 7 | `FuzzMultiTenantIsolation` | server/http | cross-tenant isolation (REST API sequence) | high | 6 (low) | ✅ 18m |
| 8 | `FuzzSSOIDTokenSingleConstraintViolation` | internal/core | issuer-cannot-widen, interactive SSO login | high | 21 (low) | ✅ 18m |
| 9 | `FuzzOIDCIDTokenSingleConstraintViolation` | internal/core | issuer-cannot-widen, OIDC k8s/service-account | high | 24 (low) | ✅ 18m |
| — | `FuzzMultiTenantIsolationGRPC` | server/http | cross-tenant isolation (gRPC) | high | — | leftover |
| — | `FuzzConnectRefScopingGRPC` extra | server/http | (still growing at 18m) | high | — | leftover |
| — | `FuzzGormListTenantIsolation` | internal/storage/store | tenant isolation at the SQL layer | high | — | leftover |
| — | `FuzzReconcileAuthzBoundary` | operator | operator reconcile authz boundary | med | — | leftover |
| — | `FuzzDecodePATScopes` / `…CIDRs` / `FuzzPATValidateLifecycle` | internal/core(/rules) | PAT parse/lifecycle | med | — | leftover |
| — | `FuzzVerifyIDToken` / `FuzzVerifyIDTokenClaims` / `FuzzReturnToOpenRedirectDifferential` / `FuzzValidateSCIMTokenStrength` | internal/core(/rules) | SSO/OIDC/SCIM boundary | med–high | — | leftover |

## §2 Run results

| Target | Fuzz min | Execs (≈) | New-interesting (corpus) | Crashers | Result |
|--------|---------:|----------:|--------------------------|---------:|--------|
| `FuzzAuthzDiff` | 27 | 37,600 | +230 (3563→3793) | 0 | PASS, 0 unexplained/uncalibrated |
| `FuzzAuthzSeq` | 18 | 211 (≈11/min; each exec is a full multi-step stateful scenario) | +29 (51→80) | 0 | PASS, 0 ALWAYS-FAIL/CANDIDATE |
| `FuzzChiAuthzRouteDifferential` | 18 | 2,100,000 | +3 (213→216) | 0 | PASS — **saturated** |
| `FuzzGRPCRESTSecretReadAuthzParity` | 18 | 17,800 | +95 (11→106) | 0 | PASS — **still growing** |
| `FuzzPATRestrictionAllows` | 18 | 13,800,000 | +47 (5→52) | 0 | PASS — **saturated** (+0 in chunk 2) |
| `FuzzConnectRefScopingGRPC` | 27 | 76,000 | +176 (8→184) | 0 | PASS — **still growing** (extended) |
| `FuzzMultiTenantIsolation` | 27 | 27,000 | +143 (6→149) | 0 | PASS — **still growing** (extended) |
| `FuzzSSOIDTokenSingleConstraintViolation` | 18 | 225,000 | +151 (21→172) | 0 | PASS — 0 constraint bypass |
| `FuzzOIDCIDTokenSingleConstraintViolation` | 18 | 378,000 | +137 (24→161) | 0 | PASS — 0 constraint bypass |
| **Total** | **189** | — | — | **0** | **all green** |

The two "still growing" server/http isolation targets each received an extra 9 min chunk
after the main pass (ConnectRef 136→184, MultiTenant 107→149); both kept finding new
coverage with **0 crashers**, confirming they remain the best place to spend further time.

"Still growing" = corpus was non-trivially expanding at the end of the budget → the most
valuable place to spend additional fuzz time (see §6). "Saturated" = new-interesting had
flattened to ~0, further time has low marginal value.

Post-run verification: `git status --porcelain` shows **no new files under any
`testdata/fuzz/`** — the fuzzers found nothing worth minimising into a regression seed.

## §3 membership.invite crasher classification — **ARTIFACT (no crasher exists)**

- **testdata/fuzz:** `server/authzdiff/testdata/fuzz/FuzzAuthzDiff/` contains exactly one
  file, `f1be67fcde954c04`. Its content is a `machine.token.issue` input (a custom-role
  user over a `project_auditor` machine it does not cover), committed as a *passing*
  regression seed in 2538b2ac01 after the model fix 9cd3ce4fd3. It is **not** a
  membership.invite input and it does **not** crash.
- **git history of the target:** no commit introduces or references a `membership.invite`
  crasher; `git log -S 'membership.invite' -- server/authzdiff` returns only the
  harness-construction commits.
- **deterministic replay:** `go test ./server/authzdiff -run '^FuzzAuthzDiff$'` (replays the
  on-disk seed corpus) → **PASS**, 0.74 s, 3× (re-run during the campaign, stable).
- **live fuzzing:** 27 min / ~37.6k execs of `FuzzAuthzDiff` (which cycles `membership.invite`
  as one op in its rotation — `server/authzdiff/ops_families_test.go:298`) produced **0**
  unexplained/uncalibrated cases.

`membership.invite` is a fully-covered op (COVERAGE.md: memberships 5/5, 100%). Its oracle
checks that the REST `POST /projects/{id}/memberships`, the gRPC `InviteMember`, and
`core.InviteMember` agree against the derived requirement `roles.assign @project` under a
ceiling (`grantRole`-derived role at the project). Nothing in 171 min of fuzzing, or in the
seed corpus, or in git history, shows a divergence. **Conclusion: the task's "open crasher"
is an artifact — it is not present in this repository state.** (If the orchestrator holds an
input believed to reproduce one, it was not committed to the branch and could not be located;
the live target is green.)

## §4 What each oracle does NOT verify (honest scope limits)

- **`FuzzAuthzDiff`** — compares REST vs gRPC vs core *allow/deny* (and calibrated
  flagged-difference buckets) for single operations against a derived requirement+ceiling
  model. Does **not** verify: response *bodies/field-level* content beyond allow/deny;
  multi-step state (that is `FuzzAuthzSeq`); real network transport, TLS, or the chi
  middleware stack (it drives core/service layers, not the HTTP router — route-gating is
  `FuzzChiAuthzRouteDifferential`'s job); timing/rate-limit paths except where explicitly
  calibrated; and any op not in `ops()` (the matrix is only as complete as that enumeration).
- **`FuzzAuthzSeq`** — explores *sequences* of operations for an "always-fail" or
  late-diverging class. Extremely low throughput (~11 execs/min) → it exercises only a
  shallow slice of the sequence space per unit time; a genuinely deep (6+ step) interleaving
  bug could sit beyond what 18 min reaches. Does **not** verify single-op parity (that is
  `FuzzAuthzDiff`) and does not model concurrent/racing sequences.
- **`FuzzChiAuthzRouteDifferential`** — drives the real PAT-restriction middleware + chi
  router over fuzzed `method+path` and fails on CH1-A/CH1-B authz-vs-routing divergence or a
  new CH1-C routing class. Does **not** verify body-level authz, non-PAT auth principals, or
  anything about the handler *behind* the gate — only that the gate's refuse/allow matches
  `core.RestrictedPATWriteRefusal` for the matched route. Saturated → structurally
  path-shaped inputs are well covered.
- **`FuzzGRPCRESTSecretReadAuthzParity`** — only the **secret *read*** path, REST vs gRPC.
  Does **not** cover write/delete/list parity, non-secret resources, or ref formats outside
  the fuzzed grammar. Was still growing at 18 min → under-explored.
- **`FuzzPATRestrictionAllows`** — metamorphic over PAT scope/CIDR allow decisions using a
  small realistic vocab + raw edge tokens. Saturated. Does **not** verify PAT *lifecycle*
  (issue/rotate/revoke — `FuzzPATValidateLifecycle`) or the wire decoding of scopes/CIDRs
  (`FuzzDecodePATScopes`/`…CIDRs`); it checks the *matcher's* algebra, not storage or transport.
- **`FuzzConnectRefScopingGRPC`** — a project-scoped PAT must not read another project's
  connector ref over gRPC. Does **not** cover the REST equivalent, non-connector refs, or
  write scoping. Still growing at 18 min → under-explored.
- **`FuzzMultiTenantIsolation`** — REST API *sequence* world; tenant A's token must never
  reach tenant B's secret. Does **not** cover the gRPC surface (`…IsolationGRPC`, a
  leftover) or the SQL-layer isolation (`FuzzGormListTenantIsolation`). Still growing.
- **`FuzzSSOIDTokenSingleConstraintViolation` / `FuzzOIDCIDTokenSingleConstraintViolation`**
  — build a JWT with **exactly one** tampered constraint (iss/aud/exp/nbf/iat/kid/alg/sub,
  plus nonce for SSO, max-age for OIDC) and assert the verifier rejects any single violation
  and accepts the zero-violation token with the correct identity. Does **not** verify:
  *combinations* of violations (only single); JWKS *fetching*/rotation/network behaviour (a
  static key resolver is used — see `FuzzJWKSHostileIdP` for that); replay/nonce-store
  semantics beyond presence/match; or claims outside the enumerated `*JWTViolationKinds` set
  (the guarantee is only as complete as that kind list).

## §5 Issue-ready proposals

**None.** No finding in this campaign requires a production change. The authz oracles held
green throughout; the single task-named item is an artifact, not a defect. Recording
"nothing owed" explicitly, per the repo's own guidance that a guard nobody has watched fail
is weak evidence — here the guards *were* watched (171 min live) and did not fire.

One **non-blocking harness observation** (not a production issue, not actioned to honour "no
new harness features unless a finding forces it): `FuzzAuthzSeq`'s ~11 execs/min means a
540 s chunk explores very few sequences. If sequence-space coverage is a goal, a future
harness PR could cache the per-step world setup across execs; this is an efficiency note,
not a correctness finding, and is out of scope here.

## §6 LEFTOVERS (ranked by expected value of more fuzz time)

1. **`FuzzConnectRefScopingGRPC`** (server/http) — *still growing* (+128 corpus, +55 in the
   2nd chunk). Highest-value continuation: cross-project connector-ref isolation over gRPC,
   low prior time, clearly under-explored. Recommend ≥30 more min.
2. **`FuzzMultiTenantIsolation`** (server/http) — *still growing* (+101). Cross-tenant secret
   isolation; under-explored. Recommend ≥30 more min, plus:
3. **`FuzzMultiTenantIsolationGRPC`** (server/http) — the gRPC twin, **not run** this
   campaign. Same blast radius (cross-tenant read) on the other transport.
4. **`FuzzGRPCRESTSecretReadAuthzParity`** (server/http) — *still growing* (+95). Extend the
   fuzzed op set beyond secret-read if the harness allows; or just give it more time.
5. **`FuzzAuthzSeq`** (server/authzdiff) — throughput-bound; the deep-sequence authz bugs it
   targets need either much longer wall time or the setup-caching efficiency note in §5.
6. **`FuzzGormListTenantIsolation`** (internal/storage/store) — tenant isolation at the SQL
   layer; complements the HTTP/gRPC isolation fuzzers at a different layer. Not run.
7. **`FuzzReconcileAuthzBoundary`** (operator) — operator reconcile authz boundary; separate
   code path (controller), not touched by any target above.
8. **`FuzzVerifyIDToken` / `FuzzVerifyIDTokenClaims` / `FuzzReturnToOpenRedirectDifferential`
   / `FuzzValidateSCIMTokenStrength`** (internal/core, internal/core/rules) — the broader
   SSO/OIDC/SCIM identity boundary beyond the single-constraint pair run here.
9. **PAT parse/lifecycle:** `FuzzDecodePATScopes`, `FuzzDecodePATCIDRs`,
   `FuzzPATValidateLifecycle` (internal/core(/rules)) — complete the PAT surface
   (`FuzzPATRestrictionAllows` only covers the matcher algebra, already saturated).

## Appendix — run commands & logs

All runs: `nice -n 10 env GOMAXPROCS=2 go test <pkg> -run '^$' -fuzz '^<Target>$'
-fuzztime 540s -parallel 2`. Per-chunk logs under `.scratch/fuzzlogs/`. Caches pinned to
`/mnt/data/wave4/gocache` + `/mnt/data/wave4/gomod` (pre-configured in `go env`).
`KEYORIX_TEST_PG_DSN` was present in the environment throughout (so any target that wanted
Postgres had it); the `server/authzdiff` and `internal/core` targets use in-memory harnesses
and the `server/http` targets build their own test storage. I created **no** `az3_`-prefixed
database, and the campaign created none, so there is nothing to drop.
