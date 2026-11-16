# scripts/ci/authzgate — the authz-oracle PR gate

`ci.yml`'s `fuzz-plan` job runs `scripts/ci/authz-oracle.sh plan`; the
`authz-oracle` job runs `scripts/ci/authz-oracle.sh run`. Together they run the
`server/authzdiff` strict sweep when a pull request changes permission-check
code, so a rule change without the matching reference-model change fails on
the PR instead of on a fuzz lane hours later (AUTHZ-MODEL-GUARD-1, registry
KFZ-2026-092, the #4332 IssueMachineToken ceiling).

How the trigger set and the op mapping are derived, and what they do not see:
the header of `main.go`. To look at them:

```
go run ./scripts/ci/authzgate inventory          # the trigger set (and the closure's stops)
go run ./scripts/ci/authzgate plan -base origin/main
go run ./scripts/ci/authzgate ops                # the op table as parsed
scripts/ci/authz-oracle.sh run ops machine.token.issue
```

## Rollout

The `authz-oracle` check is red whenever the sweep is. It feeds the required
`fuzz-changed` context only when the repository variable
`AUTHZ_ORACLE_GATE=enforce` is set. Until the #4332 model fix
(`fuzz/authzdiff-model-4332`) is on main, main itself fails
`machine.token.issue`, so enforcing earlier would block every PR that maps to it.

## Measured (2026-11-16)

Local (Apple silicon, warm build cache; `go test` wall time):

| run | wall | CPU (user) | result on main 58e70c1f1 |
|---|---|---|---|
| `go test ./server/authzdiff` (default tests) | 21 s | 17 s | pass: the default tests do not see #4332 |
| strict sweep, `AUTHZDIFF_OPS=machine.token.issue` | 11 s (sweep 0.8 s) | 8 s | **fail**: 8 unexplained cases (custom role {roles.assign}, user/group route: model allows, core/REST/gRPC deny) |
| strict sweep, all 95 ops (55,595 cases) | 518 s | 1,775 s | **fail**: the same 8 cases, nothing else unexplained, no dead waiver |
| 60 s `FuzzAuthzDiff` burst, GOMAXPROCS=2, warm corpus cache | 82 s | 140 s | pass: the whole minute went to replaying 1,353 of 2,022 cached inputs, no new input fuzzed |
| same burst, empty cache (CI's start: 2 seeds) | 17 s | 23 s | fail after 10 s on an UNRELATED case (group.restore, suspended principal, gRPC `ResourceExhausted`); replayed alone it is the waived `known-04` with gRPC `Unauthenticated`, 5/5 |

So the burst is not a PR gate: within 60 s it does not reliably reach the
#4332 case, and it can fail on harness state that has nothing to do with the
PR. It runs only on `ci:full`, report-only.

Trigger rate over the last 100 merged PRs (#4251 … #4345, `git log
--first-parent --merges -100 origin/main`, plan of each merge against its first
parent with this tool):

| plan | PRs |
|---|---|
| none | 93 (8 of them touched permission-check code no authzdiff op reaches: SSO login, legal hold, admin CLI, start-up) |
| ops | 2: #4332 (`machine.token.issue`), #4283 (4 ops) |
| full | 2: #4203 (`LocalStorage.CreateRole`, a storage root), #4172 (`server/authzdiff` itself) |
| ci.yml canary (2 ops) | 3: #4341, #4331, #4221 |

The CI runner cost of one triggering PR is in the introducing PR's body
(measured on its own run).
