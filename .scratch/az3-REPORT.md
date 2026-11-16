# az3 — Long real-time runs of the extended authorization differential (task V5-long)

**Branch:** `fuzz/authz-long-runs` (stacked on az2 "extended authzdiff model")
**Worktree:** `/mnt/data/wave4/az3` (standalone clone on pve01)
**Report path note:** `/mnt/data/wave4/out/` is **not writable from this sandbox**
(blocked: outside the session working directory). Per the runtime rules the report
is therefore kept committed on the branch at **`.scratch/az3-REPORT.md`**.
**Temperature note:** `/sys/class/hwmon/hwmon2/temp1_input` is **unreadable from this
sandbox** (outside the working directory; blocked even with sandbox override). Thermal
safety is therefore enforced only by `nice -n 10`, `GOMAXPROCS=2` and `-parallel 2`,
as the rules allow.

## Interpretation of the task (stated up front, nobody to ask)

- The task names "the open crasher FuzzAuthzDiff membership.invite". **No such crasher
  file exists** in `server/authzdiff/testdata/fuzz/FuzzAuthzDiff/` (the only on-disk
  corpus entry is `f1be67fcde954c04`, a *passing* regression seed for
  `machine.token.issue` committed in 2538b2ac01), and no membership.invite crasher
  appears in the git history of the target. The on-disk seed corpus replays green
  (`go test -run '^FuzzAuthzDiff$'` → PASS, 0.74s). I read this as: there is no open
  crasher; `membership.invite` is a fully-covered op (COVERAGE.md: memberships 5/5
  100%) whose differential is calibrated. Details in §3.
- `az2-REPORT.md` is not present in this clone; the az2 work is the 10 commits on this
  branch above `origin/main` (extended authzdiff model + middleware bcrypt-storm caps).
  I reconstructed az2 state from `server/authzdiff/` and those commits.
- "No new harness features except what a finding forces; no production changes." Honoured:
  this run is read-only fuzzing. Any finding that would need a production change is written
  below as an issue-ready proposal, not applied.
- Env: caches are pre-pointed (`GOCACHE=/mnt/data/wave4/gocache`,
  `GOMODCACHE=/mnt/data/wave4/gomod`); runs use `nice -n 10 env GOMAXPROCS=2 go test …
  -parallel 2`. `KEYORIX_TEST_PG_DSN` is present (PostgreSQL 17 LXC). Fuzz wall time is
  counted from the fuzzer's own `elapsed:` line, not tool wall time.

## §1 Authz-related fuzz targets, ranked

Ranked by (risk of an authz bypass if the oracle is weak × how little dedicated fuzz time
the target has had). Prior fuzz time is inferred from cached-corpus size and commit recency.

| # | Target | Pkg | Category | Risk | Prior time | Planned |
|---|--------|-----|----------|------|-----------|---------|
| 1 | `FuzzAuthzDiff` | server/authzdiff | REST/gRPC/core authz differential (the extended model) | critical | high (3563-entry cached corpus) | run (primary) |
| 2 | `FuzzAuthzSeq` | server/authzdiff | stateful authz sequence differential | critical | lower | run |
| 3 | `FuzzChiAuthzRouteDifferential` | server/middleware | router authz-gate vs matrix differential | critical | medium | run |
| 4 | `FuzzGRPCRESTSecretReadAuthzParity` | server/http | REST↔gRPC secret-read authz parity | high | medium | run |
| 5 | `FuzzPATRestrictionAllows` | internal/core/rules | PAT scope/CIDR restriction metamorphic | high | medium | run |
| 6 | `FuzzConnectRefScopingGRPC` | server/http | connector-ref scope isolation (gRPC) | high | low | run |
| 7 | `FuzzMultiTenantIsolation` / `…GRPC` | server/http | cross-tenant isolation | high | low | run if budget |
| 8 | `FuzzSSOIDTokenSingleConstraintViolation` / `FuzzOIDCIDTokenSingleConstraintViolation` | internal/core | issuer-cannot-widen (SSO/OIDC single-constraint) | high | medium | run if budget |
| — | `FuzzReconcileAuthzBoundary` | operator | operator authz boundary | med | low | leftover |
| — | `FuzzGormListTenantIsolation` | internal/storage/store | tenant isolation at SQL layer | high | medium | leftover |
| — | `FuzzDecodePATScopes`/`…CIDRs`/`FuzzPATValidateLifecycle` | internal/core(/rules) | PAT parse/lifecycle | med | medium | leftover |

## §2 Run results (updated as chunks complete)

| Target | Fuzz min | Execs | New-interesting | Crashers | Result |
|--------|---------:|------:|----------------:|---------:|--------|
| `FuzzAuthzDiff` (server/authzdiff) | 27 | ~37,600 | +230 (corpus 3563→3793) | 0 | PASS, 0 unexplained/uncalibrated |
| `FuzzAuthzSeq` (server/authzdiff) | 18 | ~211 (≈11/min, each exec is a full multi-step stateful scenario) | +29 (corpus 51→80) | 0 | PASS, 0 unexplained |
| _(more below as chunks complete)_ | | | | | |

## §3 membership.invite crasher classification

**Classification: ARTIFACT (no crasher exists).** See §2/appendix once runs complete.
Preliminary: no crasher file on disk, none in git history; seed corpus green.

## §4 What each oracle does NOT verify

_(filled per target during the run)_

## §5 Issue-ready proposals

_(none yet)_

## §6 LEFTOVERS (ranked)

_(filled at the end)_
