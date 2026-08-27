# G80 Wave 0: RemoteStorage surface partition

Investigation only, run in a dedicated worktree off current `origin/main`
(commit at time of writing: see `git log -1` in this worktree). No deletions
in this pass. This document is the map; the deletion is a separate,
follow-up pass against this evidence.

## CORRECTION (G80 Wave 0c) — read this first

This document originally classified `GetLatestSecretVersion` as **LIVE —
confirmed**, on the strength of `run/run.go:181` (`svc.GetSecretValue`)
appearing on the "23-file unconditional core-path" list below with no
`common.NewRemoteClient()` guard. That verdict was wrong, and it drove the
next task's entire framing ("`keyorix run` 404s on every secret fetch under
`storage.type: remote` today... the product's headline command does not
work in its primary multi-user configuration").

**What was believed:** the raw-HTTP-passthrough guard idiom was
`common.NewRemoteClient()`, and grepping for its absence was sufficient to
identify every CLI command that unconditionally reaches `RemoteStorage`.

**What was actually true:** `run.go` calls `common.ResolveRemote()`
directly at line 102 — the function `NewRemoteClient()` itself wraps — as
its own, independently-implemented guard. `common.NewRemoteClientWithCredentials()`
is a third call into the same family. The exclusion grep only knew about
one of three idioms in active use across `internal/cli`.

**How this was found:** direct, live testing (G80 Wave 0b) — running
`keyorix run` against a real hub server under a complete `storage.type:
remote` config printed the correct secret value and exited 0. Re-tracing
from that observed result, not from another grep, surfaced `ResolveRemote()`.

**What replaced it:** Task 1 below (Wave 0c) derives the complete idiom set
from the code — every exported function in `internal/cli/common` that
builds a raw remote HTTP client or resolves remote credentials, confirmed
against an independent search for any command rolling its own `net/http`
client or branching directly on `Storage.Type`/`IsClientMode()` — and
re-runs the exclusion against that set. The result: `run.go` is the only
file affected. `GetLatestSecretVersion` moves from LIVE to the same
DEAD-in-practice (guarded) bucket as the other 9 `#1511` methods that were
already classified that way — see the corrected Task 2 table below, which
keeps the original verdict struck through rather than deleted.

The live sweep this correction is based on also surfaced a genuine, broad
break (11 CLI commands, unrelated root cause) that the original static
partition did not predict — filed as
[#1575](https://github.com/keyorixhq/keyorix/issues/1575). See "Task 1 —
re-derived idiom set" and the sweep table below.

## Headline finding: two CLI mechanisms, not one

The task brief (and the existing `remoteUnsupportedAllowlist` reasoning
built up over ~10 prior rounds) frames `storage.type: remote`'s live
surface as "the CLI." That's true but imprecise in a way that matters a
lot for this partition. The CLI actually has **two independent
mechanisms** for talking to a remote hub, and which one a given command
uses determines whether `RemoteStorage`'s Go implementation is ever
actually invoked:

- **Mechanism A — raw HTTP passthrough (`common.NewRemoteClient()`).**
  `ResolveRemote()` (`internal/cli/common/remote_client.go:56`) resolves an
  endpoint+token from `KEYORIX_SERVER`/`KEYORIX_TOKEN`, `~/.keyorix/cli.yaml`,
  or — critically — `mainCfg.Storage.Remote.BaseURL`/`GetAPIKey()`, i.e. the
  **same** `storage.type: remote` config that the factory uses. When it
  resolves (any complete remote config), the command issues a plain
  `net/http` request directly against the hub's REST API and returns —
  `core.KeyorixCore` and `RemoteStorage` are never constructed for that
  command at all.
- **Mechanism B — core-in-process (`common.InitializeCoreService()` /
  `common.InitializeStorage()`).** Builds a real `core.KeyorixCore` backed
  by whatever `factory.CreateStorage(cfg)` returns — `*RemoteStorage` when
  `cfg.Storage.Type == "remote"`. Business logic (validation, permission
  checks, audit) runs **client-side**, with `RemoteStorage` doing the
  actual I/O over HTTP. This is the mechanism ADR-083 confirmed is real
  and intentional ("the entire reason this storage type exists").

The decisive fact: **almost every feature-complete CLI command checks
Mechanism A first and only falls through to Mechanism B when
Mechanism A is unavailable** (`if rc, ok := common.NewRemoteClient(); ok {
...; return }`). Verified directly in `secret/{get,create,update,list,
folder,bulk_delete}.go`, `share/{create,update,revoke,list,shared_secrets}.go`,
`project/{create,stats}.go`, `rbac/{assign_role,remove_role,check_permission,
audit_logs,group_role,export_matrix,list_permissions,list_user_roles,
list_roles}.go` — every one of these guards remote mode into Mechanism A.
Since `ResolveRemote()` falls back to the exact same `storage.type: remote`
config Mechanism B would use, **any correctly-configured remote setup
satisfies Mechanism A first**, so Mechanism B's `RemoteStorage` calls in
these files are unreachable in normal operation — not because the server
topology is forbidden, but because a sibling code path in the *same
binary* always wins the race first.

Mechanism B only genuinely executes against `RemoteStorage` for CLI
commands that have **no** `NewRemoteClient()` guard at all. Exhaustively
enumerated (`comm -23` of the `InitializeCoreService()` caller list against
the `NewRemoteClient()` caller list):

```
group/{create,delete,get,list,members,update}.go   (not add-member/remove-member — those ARE guarded)
invite/{list,resend,revoke,send}.go
migrate/user_to_machine.go
request/{access,list,review,secret_access,withdraw}.go
run/run.go
status/status.go
user/{delete,get,lifecycle,list,setup_link,update}.go
```

This ~23-file set is the **true, current, live CLI-via-core surface** for
`RemoteStorage`. It is much narrower than "the CLI" as a whole, and
narrower than the surface the existing 75-entry `remoteUnsupportedAllowlist`
implicitly assumes when it says e.g. "the CLI uses the HTTP handler via
POST /api/v1/X" — that reasoning is *correct*, and this finding is the
general mechanism behind each of those per-feature observations, named
explicitly for the first time. It does not overturn any of that prior
work; it explains why it was right and gives a precise test for the
methods that prior work didn't cover.

**This is a refinement worth flagging per the guardrails, not a rebuttal
of ADR-083 or the server-topology premise.** ADR-083 traced
`AuthorizePrincipal` (the HTTP/gRPC-middleware entry point) and correctly
concluded `GetUserRoleIDsAt`/`GetUserGroupRoleIDsAt`/`RoleSetHasPermission`
are hard stubs with no working caller *through that entry point*. What
ADR-083's own evidence table didn't examine is `core.Authorize` — a
**second, independent entry point into the identical stub chain**, called
directly (no router, no middleware) by `invite/send.go:93`,
`request/list.go:87`, `request/review.go:136`, and
`migrate/user_to_machine.go:119,126` — all four in the unguarded set
above. So these three methods are not *only* reachable from the forbidden
server topology after all: they are also live-reachable today via four
specific CLI commands running in Mechanism B. Deleting them outright (as
ADR-083's deferred-work section gestures toward) would break those four
commands under `storage.type: remote`. See Task 1 below.

## Current true stub-surface size (the "26" figure is stale)

The task brief's "a prior triage found 26 stub methods" does not match
current `origin/main`. What actually exists:

| Category | Count | Tracked by |
|---|---|---|
| `remoteUnsupported("X")`-wrapped stubs, individually classified `statusIntentional` | **75** | `remoteUnsupportedAllowlist` + `TestRemoteUnsupportedStubsAreAllowlisted` (green) |
| Raw `fmt.Errorf("not supported in remote storage")` stubs — bypass the allowlist tracking entirely (regex only matches the `remoteUnsupported(...)` call shape) | **13** | Nothing — no completeness guard covers this shape |
| Wire calls with no matching `router.go` route (real HTTP calls, not stubs — different defect shape) | **13** | `knownMissingRoutes` in `remote_wire_route_coverage_test.go` (green) — this **is** issue #1511's own tracking list, confirmed by exact count and path match |

88 stub-shaped methods, not 26. The 13 raw stubs are the ones that most
resemble what a "prior triage" without the mature allowlist tooling would
have flagged by hand — `IsProjectMember` among them, undocumented (zero
doc comment, unlike every sibling in the same block), which is exactly
why #1512 called it out specifically.

The 75 already-classified stubs are **not re-audited from scratch here** —
that would be redoing verified prior work outside this task's scope. But
the Mechanism A/B finding above is new evidence those 75 classifications
didn't have access to, and a handful of their stated reasons ("no remote
caller ever invokes this directly") are worth spot-checking against it in
a follow-up pass — flagged as a Wave 1/2 recommendation, not resolved here.

## Task 1 — partition of the 13 raw (unclassified) stubs

| Method | Bucket | Caller path | Decisive file:line |
|---|---|---|---|
| `IsProjectMember` | **UNRESOLVED, evidence leans DEAD-in-practice** | `requireLiveOwnerAuthority`/`ShareSecret`/`ShareSecretWithGroup` — every non-server caller sits behind a `NewRemoteClient()` guard (`share/create.go:52`); `ActivateBreakGlass` caller is server/grpc-only | `internal/core/permissions.go:55`, `internal/cli/share/create.go:52` |
| `IsGroupProjectScoped` | **UNRESOLVED, evidence leans DEAD-in-practice** | Sole caller `ShareSecretWithGroup`, same guarded path as above | `internal/core/group_sharing.go:54` |
| `GetUserRoleIDsAt` | **LIVE** | `Authorize`→`scopedRoleIDs`, called directly (no guard) by `invite/send.go`, `request/{list,review}.go`, `migrate/user_to_machine.go` | `internal/core/authz.go:222`, `internal/cli/invite/send.go:93` |
| `GetUserGroupRoleIDsAt` | **LIVE** | Same `scopedRoleIDs` chain as above | `internal/core/authz.go` (`scopedRoleIDs`) |
| `RoleSetHasPermission` | **LIVE** | Same `Authorize` chain, final step | `internal/core/authz.go:236` |
| `GetUserRoleIDsExact` | **UNRESOLVED** | `internal/core/project_members.go:50,99` (add/remove project member) — no CLI caller found for those specific core functions in the time available; not confirmed HTTP-only either | `internal/core/project_members.go:50` |
| `GetUserRoleScopes` | **UNRESOLVED, evidence leans LIVE** | `authz.go:568`, `connect.go:258,641`, `rbac.go:86` — `connect.go` is Keyorix Connect (`connect ...` CLI subtree), not fully traced this pass | `internal/core/connect.go:641` |
| `GetMachineRoleScopes` | **UNRESOLVED, evidence leans LIVE (mirrors GetUserRoleScopes)** | `connect.go:256` — same Connect path, not fully traced | `internal/core/connect.go:256` |
| `GetUserGroupPermissions` | **UNRESOLVED** | `internal/core/sod.go:306` (SoD conflict detection), `rbac_management.go:268` — not traced to a CLI entry point this pass | `internal/core/sod.go:306` |
| `CreatePermission` | **DEAD** | Only caller `auth_bootstrap.go:278` (bootstrap-time seeding) and `rbac_reconcile.go:41` — both server-boot-only, no CLI path | `internal/core/auth_bootstrap.go:278` |
| `AssignPermissionToRole` | **UNRESOLVED, evidence leans DEAD** | `rbac_management.go:97` reached from `server/http/handlers/rbac.go` (3 call sites) and `server/grpc/services/role_service.go` (2); `auth_bootstrap.go:301`/`rbac_reconcile.go:82` are boot-only. No CLI caller found. | `internal/core/rbac_management.go:97` |
| `CreateProject` | **DEAD-in-practice (guarded)** | `internal/cli/project/create.go` checks `NewRemoteClient()` first (line 53) and posts directly to `/api/v1/projects`; the `svc.CreateProject` fallback (line 77) only runs in embedded/local mode | `internal/cli/project/create.go:53,77` |
| `CreateEnvironment` | **DEAD-in-practice (guarded)** | Same shape as `CreateProject`, in `project/env.go` | `internal/cli/project/env.go` |

## Task 2 — the 13 #1511 orphaned wire calls, by bucket

Mapped each `knownMissingRoutes` entry to its `RemoteStorage` method and
traced the method's callers:

| # | routeKey | Method | Bucket | Evidence |
|---|---|---|---|---|
| 1 | `POST /api/v1/secrets/*/versions` | `CreateSecretVersion` | **DEAD-in-practice (guarded)** | Reached only via `CreateSecret`/`UpdateSecret`, both behind `NewRemoteClient()` in `secret/create.go`, `secret/update.go` |
| 2 | `POST /api/v1/sessions/cleanup` | `CleanupExpiredSessions` | **DEAD** | Zero callers anywhere, in any topology — `internal/core/users.go:448` itself notes "implemented but never scheduled" |
| 3 | `POST /api/v1/rbac/assign-role` | `AssignRole` | **DEAD-in-practice (guarded)** | `rbac_management.go` version reached only via `rbac/assign_role.go`, guarded; other callers (`users.go`, `sso.go`, `scim.go`, `auth_bootstrap.go`) are HTTP/bootstrap-only |
| 4 | `POST /api/v1/rbac/remove-role` | `RemoveRole` | **DEAD-in-practice (guarded)** | Same shape as #3, via `rbac/remove_role.go` |
| 5 | `PUT /api/v1/system/risk-exceptions/*` | `UpdateRiskException` | **DEAD — already confirmed by a prior round** | `server/http/handlers/risk_exceptions_proxy.go:175-186` (G79) already states: "a repo-wide search found no caller of it anywhere, local or remote" — the proxy route was deliberately removed for exactly this reason. #1511's entry is stale; the route removal already happened. |
| 6 | `POST /api/v1/shares` | `CreateShareRecord` | **DEAD-in-practice (guarded)** | Only reached via `ShareSecret`/`ShareSecretWithGroup`, guarded (`share/create.go`) |
| 7 | `GET /api/v1/shares/*` | `GetShareRecord` | **DEAD-in-practice (guarded)** | Only reached via share update/revoke, guarded (`share/{update,revoke}.go`) |
| 8 | `GET /api/v1/stats` | `GetStats` | **DEAD** | Sole caller `GetDashboardStats`, sole caller of *that* is `server/http/handlers/dashboard.go` — no CLI path at all |
| 9 | `GET /api/v1/secrets/*/versions/*` | `GetSecretVersion` | **DEAD** | No CLI caller found for any wrapper (`versions.go`, `secret_version_diff.go`) — tags/move/suspend/description/diff-class features are HTTP/gRPC-only, not exposed via any CLI command |
| 10 | `GET /api/v1/secrets/*/versions/latest` | `GetLatestSecretVersion` | ~~LIVE — confirmed~~ → **DEAD-in-practice (guarded)** (corrected, Wave 0c) | Original verdict relied on `run/run.go:181` (`svc.GetSecretValue`) appearing unguarded. It isn't: `run.go:102` calls `common.ResolveRemote()` directly — a guard idiom the original exclusion grep didn't know to look for. Under any complete `storage.type: remote` config, `remoteOK` is true and `run` takes `fetchSecretsRemote` (raw HTTP via `common.NewRemoteClientWithCredentials`), never `fetchSecretsEmbedded`/`RemoteStorage`. Confirmed live: `keyorix run` against a real hub prints the correct secret value and exits 0. See "Task 1 — re-derived idiom set" below. |
| 11 | `POST /api/v1/secret-versions/*/increment-read-count` | `IncrementSecretReadCount` | **DEAD** | Zero callers in `internal/core` at all (distinct from the separate, already-classified `TryIncrementSecretReadCount`); the method's own sibling doc comment already says "not on the live remote value-read path today" |
| 12 | `GET /api/v1/users/*/shared-secrets` | `ListSharedSecrets` | **DEAD-in-practice (guarded)** | CLI caller `share/shared_secrets.go:60` sits behind `NewRemoteClient()` (line 30) |
| 13 | `GET /api/v1/secrets/*/permissions` | `CheckSharePermission` (core-level) | **DEAD** | Zero callers anywhere outside test files — orphaned even server-side |

~~**Split: 4 DEAD outright + 6 DEAD-in-practice (guarded) = 10 of 13 close by
deletion. 1 (`GetLatestSecretVersion`) is a confirmed, currently-live gap
— `keyorix run` under `storage.type: remote` 404s on every secret value
fetch today.**~~ **Corrected (Wave 0c): all 13 are now some flavor of DEAD.**
5 DEAD outright (zero caller in any topology: `CleanupExpiredSessions`,
`GetStats`, `GetSecretVersion`, `IncrementSecretReadCount`,
`CheckSharePermission`) + 1 already-fixed/stale listing
(`UpdateRiskException`, closed by a prior G79 round) + 7 DEAD-in-practice
guarded (`CreateSecretVersion`, `AssignRole`, `RemoveRole`,
`CreateShareRecord`, `GetShareRecord`, `ListSharedSecrets`, and now
`GetLatestSecretVersion`) = 13 of 13. **Zero remain LIVE.** `run`'s
misclassification was the only error in this table; see the correction
note above `#10` and "Task 1 — re-derived idiom set" below for how that was
established and re-verified across the rest of the table (it wasn't — no
other row in this table cited `run.go` or any other file that turned out to
use `ResolveRemote()` directly, so no other row needed re-checking).

`GetLatestSecretVersion` is real, currently unfixed, and unreachable in
practice — the exact same shape as `IsProjectMember` in Task 3 below, not a
currently-live gap. It closes by deletion along with the rest of this list,
not by adding a route.

This is NOT the "none are DEAD, #1511 is entirely a real gap" outcome —
the opposite: **13 of 13 close by deletion** (corrected, Wave 0c — the
original count of 10 undercounted because `GetLatestSecretVersion` was
miscounted as a live gap needing a route; it doesn't).

## Task 1 (Wave 0c) — re-derived idiom set, and the corrected delta

The `run.go` miss (above) invalidated the exclusion-by-pattern method, not
just its one result. Before trusting any other DEAD-in-practice verdict in
this document, the idiom set had to be derived completely, not assumed.

**Derivation.** Every guard idiom found, and how completeness was
established:

1. `rg -c "NewRemoteClient\(\)|NewRemoteClientWithCredentials\(|ResolveRemote\(\)|IsClientMode\(\)" internal/cli` — the four call shapes that reach the raw-HTTP-passthrough family (`common.NewRemoteClient`/`NewRemoteClientWithCredentials` both build on `common.ResolveRemote`; `IsClientMode()` is `ResolveRemote`'s own internal cli.yaml check, also called directly by a few files). This alone matched over 100 files across `internal/cli`.
2. Independently checked for a command rolling its own HTTP client outside the `common` package (`rg "http\.Client\{|http\.NewRequest\(|http\.Get\(|http\.Post\("` in `internal/cli`, excluding `internal/cli/common/`): 4 hits, all unrelated to the file list in question (`connect.go`, `config/config.go`, `system/init.go`, `secret/source_vault.go` — a Vault-import feature).
3. Independently checked for a command branching directly on `cfg.Storage.Type == "remote"` or reading `cliconfig.LoadCLIConfig` itself rather than via `ResolveRemote`/`ResolveProject`: found only `status/status.go`'s already-known display bug (Task 2, Wave 0c below), the `encryption/*.go` commands (which *refuse* to run under remote mode outright — a third, distinct idiom, not a dual-path redirect, and not relevant to `RemoteStorage` reachability), and `connect/connect.go`/`project/{use,current}.go`/`modes.go` (none in the file list in question).

No fourth idiom was found. The search was structured to be falsifiable in
two independent directions (raw-client rollout, direct config branching),
not just a bigger regex.

**Re-running the exclusion.** `comm -23` of the `InitializeCoreService()`
caller-file list against the file list matching any of the three real
guard idioms:

```
group/{create,delete,get,list,members,update}.go
invite/{list,resend,revoke,send}.go
migrate/user_to_machine.go
request/{access,list,review,secret_access,withdraw}.go
status/status.go
user/{delete,get,lifecycle,list,setup_link,update}.go
```

22 files (was 23 — `run/run.go` correctly drops out).

**Delta against the original partition: exactly one method moved bucket.**
`GetLatestSecretVersion`, LIVE → DEAD-in-practice (guarded). Every other
DEAD-in-practice verdict in this document was independently re-checked by
confirming its cited guarding file contains one of the three real idioms
(not assumed from having contained `NewRemoteClient()` specifically) —
`share/create.go`, `share/{update,revoke,list,shared_secrets}.go`,
`secret/{get,create,update,list,folder,bulk_delete}.go`,
`project/{create,stats}.go`, `rbac/{assign_role,remove_role}.go` all do.
None used `ResolveRemote()` or `IsClientMode()` as their only guard. **The
delta is zero apart from `GetLatestSecretVersion`** — a good result, stated
plainly, not assumed.

### The live sweep (Wave 0b), corrected

All 22 files above were exercised for real against a live hub server under
`storage.type: remote` (own worktree test server, bootstrapped, real API
key). Observed exit codes and error text, not inferred:

| Command | Reaches | Route/caller present | Observed outcome |
|---|---|---|---|
| `group create/list/get/members/update/delete` | `core.CreateGroup` et al. | n/a (no RemoteStorage stub in the chain) | ✅ Works — exit 0 |
| `invite list` | `core.ListProjectInvitations` | n/a | ✅ Works — exit 0 |
| `invite send` | `core.Authorize`→`GetUserRoleIDsAt`/`RoleSetHasPermission` | Hard stubs | ❌ exit 1: `failed to verify --by authority: not supported in remote storage` |
| `invite resend` | same `requireInviteAuthority` chain | Hard stubs | ❌ exit 1, same error |
| `invite revoke` | same | Hard stubs | ❌ exit 1, same error |
| `migrate user-to-machine` | same `Authorize` chain | Hard stubs | ❌ exit 1, same error |
| `request access` | `core.RequestProjectAccess` | n/a | ✅ Works — exit 0 |
| `request list` | `requireByAuthority`→`Authorize` | Hard stubs | ❌ exit 1, same error |
| `request review` | same | Hard stubs | ❌ exit 1, same error |
| `request secret-access` | `core.RequestSecretAccess` | n/a | ✅ Works — exit 0 |
| `request withdraw` | `core.WithdrawAccessRequest` | n/a | ✅ Works — exit 0 |
| `status` | `RemoteStorage.HealthCheck`→`Health` | Route exists, response-shape mismatch | ❌ Reports "Unhealthy" against a genuinely healthy server (see Task 2, Wave 0c) |
| `user list/get/update` | `core.ListUsers` et al. | n/a | ✅ Works — exit 0 |
| `user revoke-sessions/suspend/reactivate/resend-setup-link/delete` | `requireUserAuthority`→`Authorize` | Hard stubs | ❌ exit 1, same error (5 commands) |

**13 work correctly, 11 fail via one shared root cause (`core.Authorize`'s
dependency on the three intentionally-stubbed RBAC primitives), 1
(`status`) fails via an unrelated bug.** This matches the sweep's own
stopping rule: not "most" of the 22, but far more than "a handful" — filed
as its own issue ([#1575](https://github.com/keyorixhq/keyorix/issues/1575))
rather than folded into a quick fix, per the decision that followed.

**Decision: do not implement the three stubs over the wire.** That would
have the CLI fetch role/permission data from the hub and decide locally
whether the `--by` actor is authorized — the fat-client pattern this
campaign has spent multiple rounds dismantling elsewhere. The correct
design is hub-side authorization (the CLI sends the operation + actor; the
hub decides) — a Wave 2 design question that unifies #1546, #1551, #1572,
and #1575, not a quick fix here. **Keep `GetUserRoleIDsAt`,
`GetUserGroupRoleIDsAt`, `RoleSetHasPermission` — do not delete them.**
See the ADR-083 correction (Task 3, Wave 0c) below.

Also note: the failure mode is fail-closed (refuses, never permits) — 11
commands broken is a functionality gap, not a security hole.

## Task 3 — #1512 (`IsProjectMember`) settled

This is the task's headline scoping question, and the answer updates the
task's own framing:

**Which live CLI operations call it, if any?** None found under normal,
correctly-configured `storage.type: remote` use. Both plausible live
paths traced to completion:

- `share/create.go` → `ShareSecret`/`ShareSecretWithGroup` →
  `requireLiveOwnerAuthority`/direct `IsProjectMember` call — but
  `share/create.go:52` checks `NewRemoteClient()` first and returns via
  the raw-HTTP path before ever reaching `core.NewKeyorixCore(RemoteStorage)`.
- `secret/bulk_delete.go` → `BulkDeleteSecrets` →
  `DeleteSecretWithPermissionCheck` → `EnforceSecretOwnerPermission` →
  `CheckSecretPermission` → `requireLiveOwnerAuthority` — same guard,
  `bulk_delete.go:66`, diverts to `runBulkDeleteRemote` first.

Every other call site of `CheckSecretPermission`'s wrapper functions
(`secret_tags.go`, `secret_move.go`, `secret_suspend.go`,
`secret_bulk_rename.go`, `secret_extend_expiring.go`,
`secret_access_stats.go`, `secret_access_history.go`,
`secret_audit_trail.go`, `secret_access_list.go`,
`secret_ownership_history.go`, `secret_description.go`, `certificate.go`)
has **no CLI caller at all** — those are HTTP/gRPC-only features.
`ActivateBreakGlass` and `GrantSecretACL` (the two remaining direct
`IsProjectMember` callers) are also server/grpc-only.

**Verdict: UNRESOLVED-leaning-DEAD, not LIVE as the task brief assumed.**
This directly updates the task's own premise ("blocks admin-owner secret
operations that should work") — that description was accurate for the
code shape but not for reachability once the `NewRemoteClient()` guard is
accounted for. Flagged per the guardrail instruction to stop and report
a premise-contradicting finding, even though this one is narrower than
an ADR-083-level reversal.

**What would fully settle it** (this pass used static call-graph tracing
only, not a live run): an integration test that actually constructs a
`NewRemoteClient()`-`ok=false` condition against a valid `storage.type:
remote` config (there may be a legitimate misconfiguration edge case — a
resolvable `BaseURL` with no resolvable token — that falls through to
Mechanism B; this pass did not find one that also produces a *working*
request, since `RemoteStorage`'s own HTTP client needs the same token).

**If it is DEAD, #1512 closes with the deletion** (of `IsProjectMember`
and `IsGroupProjectScoped` together, since they share the exact same
reachability shape). **If Wave 2 decides to keep the client-side
permission check as defense-in-depth** (independent of whether it's
reachable today — e.g. as a guard against a future CLI command that adds
a feature without the `NewRemoteClient()` guard), a correct
implementation needs **no new server work**: `GET
/api/v1/system/project-memberships/active?project_id=X&user_id=Y`
already exists (`server/http/router.go:1419`,
`catalogHandler.GetActiveMembershipProxy`) and answers exactly this
question — a 200 with an active membership row means "yes," anything
else means "no." This is an existing route, not a new one or a
wire-contract change.

## Task 4 — sizing the DEAD bucket

Confirmed DEAD or DEAD-in-practice this pass (excluding the 5 UNRESOLVED
raw stubs, which are not sized for deletion):

- Raw stubs: `CreatePermission`, `CreateProject`, `CreateEnvironment` (3
  confirmed) + `AssignPermissionToRole` (leans DEAD) = 3-4 methods,
  `internal/storage/store/remote_rbac.go` (partial) + a new/adjusted
  `remote_project_catalog.go`-adjacent file for `CreateProject`/
  `CreateEnvironment` (currently inline in `remote_rbac.go`).
- #1511 wire-call methods: `CleanupExpiredSessions`, `AssignRole`,
  `RemoveRole`, `UpdateRiskException`, `CreateShareRecord`,
  `GetShareRecord`, `GetStats`, `GetSecretVersion`,
  `IncrementSecretReadCount`, `ListSharedSecrets`, `CheckSharePermission`
  = 11 methods across `remote_auth.go`, `remote_rbac.go`,
  `remote_risk_exceptions.go`, `remote_sharing.go` (×3),
  `remote_stats.go`, `remote_secrets.go` (×2).
- If Task 1's 3 LIVE reclassifications are excluded from any future
  ADR-083 deferred-work deletion pass (`GetUserRoleIDsAt`,
  `GetUserGroupRoleIDsAt`, `RoleSetHasPermission` must be **kept**, not
  deleted, contrary to what ADR-083's evidence table alone might suggest).

**Rough size**: ~14 confirmed-safe method deletions across 8 files in
`internal/storage/store/`, plus their paired `_test.go` assertions and
the stale `remote_wire_route_coverage_test.go` `knownMissingRoutes`
entries (10 of 13 to remove once their methods are gone). This is a
method-body deletion, not an interface change — `storage.Storage` is an
interface every backend must satisfy, so a deleted `RemoteStorage` method
is not possible; what's actually deletable is the **wire call**, replaced
with a `remoteUnsupported("X")` stub (consistent with the other 75) or,
for the genuinely-zero-caller cases (`GetStats`, `GetSecretVersion`,
`CheckSharePermission`, `CleanupExpiredSessions`), potentially removed
from the `storage.Storage` interface entirely if `LocalStorage` also has
no live caller — **not checked this pass, would need its own trace before
touching the interface** (narrowing an interface's method set is
explicitly flagged by the task as a larger change than a deletion).

**No interface narrowing is proposed by this report.** Any of the above
could, in principle, motivate one (if `LocalStorage`'s side is also
dead), but that's a separate, larger investigation this pass didn't run.

## Guardrail check: does anything here overturn ADR-083?

No live server path boots with `storage.type: remote`. Nothing found
contradicts that. The one premise correction is narrower and specific:
ADR-083's own deferred-work section, read in isolation, could be
misread as "these hard stubs are safe to delete outright" — Task 1 shows
three of them (`GetUserRoleIDsAt`, `GetUserGroupRoleIDsAt`,
`RoleSetHasPermission`) have a second, CLI-direct caller
(`core.Authorize`) that ADR-083's `AuthorizePrincipal`-scoped trace didn't
examine. Recommend a one-line addendum to ADR-083 (not drafted here) or a
note in whatever ADR captures Wave 1's deletion, so the next person
doesn't delete a still-live path.

**Done, Wave 0c:** ADR-086 (`docs/adr-086-cli-authorize-stubs-stay.md`)
records this correction formally and supersedes the misreadable part of
ADR-083's deferred-work section. See "Task 3 (Wave 0c)" below.

## Summary table for Wave 1 scoping

~~| Bucket | Count | Action |
|---|---|---|
| LIVE (keep, real gap or real dependency) | 4 (`GetUserRoleIDsAt`, `GetUserGroupRoleIDsAt`, `RoleSetHasPermission`, `GetLatestSecretVersion`) | Keep as-is; `GetLatestSecretVersion` additionally needs a real fix (`keyorix run` is broken today under remote mode) |
| DEAD / DEAD-in-practice (safe to delete, evidence attached) | ~17 (10 of #1511's 13, minus `GetLatestSecretVersion`'s LIVE reclass and `UpdateRiskException`'s already-fixed status counted once; plus 3-4 raw stubs) | Delete in a tagged follow-up pass |
| UNRESOLVED (kept, not deleted, evidence gap named) | 7 (...) | Needs either a live-mode integration test or a deeper Connect-subtree trace before either bucket applies |~~

**Corrected (Wave 0c):**

| Bucket | Count | Action |
|---|---|---|
| LIVE (keep, real dependency) | 3 (`GetUserRoleIDsAt`, `GetUserGroupRoleIDsAt`, `RoleSetHasPermission`) | Keep as-is — confirmed by live sweep (#1575), documented in ADR-086; do NOT implement over the wire (fat-client anti-pattern), do NOT delete |
| DEAD / DEAD-in-practice (safe to delete, evidence attached) | ~18 (all 13 of #1511's list, corrected — `GetLatestSecretVersion` moved in, `UpdateRiskException` already fixed by G79; plus 3-4 raw stubs) | Delete in a tagged follow-up pass — see Task 3 (Wave 0c) below for why the deletion itself did NOT happen in this pass either |
| UNRESOLVED (kept, not deleted, evidence gap named) | 7 (`IsProjectMember`, `IsGroupProjectScoped`, `GetUserRoleIDsExact`, `GetUserRoleScopes`, `GetMachineRoleScopes`, `GetUserGroupPermissions`, `AssignPermissionToRole`) | Needs either a live-mode integration test or a deeper Connect-subtree trace before either bucket applies |

`GetLatestSecretVersion` moved from LIVE into the DEAD bucket (it was the
one delta this pass found). No method moved into or out of UNRESOLVED —
that bucket is unaffected by the idiom-gap correction; it was already
honestly incomplete for a different reason (not fully traced), not because
of a guard-idiom miss.

## Task 2 (Wave 0c) — fixed `status`, both bugs

Both isolated, no design question, both landed with tests that fail before
the fix:

1. **`RemoteStorage.Health()` envelope mismatch**
   (`internal/storage/store/remote_stats.go`). `/health`
   (`server/http/handlers/health.go`) is a deliberately minimal,
   unauthenticated, k8s-probe-style liveness endpoint — same convention as
   its sibling `/readyz` — and always returns a raw
   `{"status":"healthy",...}` body on a 2xx, never the `/api/v1/*`
   envelope (`{"success":...,"data":...}`). `Health()` checked
   `resp.Success` anyway, which defaults to `false` when the body doesn't
   carry a `"success"` key — so it reported every genuinely healthy server
   as unhealthy (`UPSTREAM_UNSUCCESSFUL: upstream returned an unsuccessful
   response with no error detail`), confirmed live against a real server
   in Wave 0b's sweep. **Fixed at the client, not the server** — `/health`
   not using the envelope is the deliberate, documented convention (it's
   outside `/api/v1/*`, listed alongside `/readyz` in router.go's
   unauthenticated-routes allowlist); `RemoteStorage.Health()` assuming
   otherwise was the deviation. `Health()` now only checks for a transport
   or 4xx/5xx error (which `rs.client.Get` already surfaces) — the mere
   absence of an error against this one endpoint is the correct signal.
   Two pre-existing tests (`TestRunStatus_RemoteUnhealthy`,
   `TestRunPing_PartialConnectivity`) had been mocking a
   `200 + {"success":false,...}` failure shape the real `/health` handler
   has no code path to ever produce — rewritten to fail via a real,
   reachable HTTP error (404) instead.
   - Proving test: `TestRemoteStorage_Health_RealServerShape`
     (`internal/storage/store/remote_storage_test.go`) — mirrors the real
     handler's exact unwrapped body; confirmed red before the fix
     (`health check failed: UPSTREAM_UNSUCCESSFUL: ...`), green after.
2. **`status.go`'s config-load bug** (`internal/cli/status/status.go`).
   `runStatus`/`runPing` called `config.Load("keyorix.yaml")` with a
   hardcoded literal, ignoring `KEYORIX_CONFIG_PATH` — the same env var
   `common.InitializeCoreService()` two lines later DOES respect. Under any
   container/env-var-configured deployment (no literal `./keyorix.yaml` in
   the CWD), the displayed "Storage Type" silently disagreed with the
   backend the health check actually ran against. Changed to
   `config.Load("")`, which resolves through the same
   `KEYORIX_CONFIG_PATH` → `./keyorix.yaml` chain `InitializeCoreService()`
   uses.
   - Proving test: `TestRunStatus_RespectsConfigPathEnvVar`
     (`internal/cli/status/status_test.go`) — points `KEYORIX_CONFIG_PATH`
     at a config file that is NOT named `keyorix.yaml`, in a directory with
     no `keyorix.yaml` either; only a fix that actually reads the env var
     can pass. Confirmed red before the fix (asserted "No configuration
     found" / "Local" instead), green after.

Both bugs, and the two rewritten tests, were verified against
`go build ./...`, `go vet`, `gofmt -l`, and the full `internal/storage/store`
and `internal/cli/status` suites (green except the 2 pre-existing,
unrelated `TestListShares_ExcludeExpiredIncludeActive`/
`TestListSharesBySecretIDs` failures in `internal/storage/store`, confirmed
by `git diff --stat` to be outside this change's touched files).

## Task 3 (Wave 0c) — ADR-083 correction, deletion held

**The deletion did not happen this pass.** Per the Wave 0c decision: no
stub implementations, no Authorize-chain fix, and — because this pass's own
`run.go` correction is the third instance of an idiom-completeness miss in
this campaign — no deletion until the corrected partition (Task 1, Wave 0c
above) has had a chance to be reviewed. The re-derivation found a clean
zero-delta result apart from `GetLatestSecretVersion`, which is reassuring,
but "reassuring" isn't the same bar as "reviewed," and the task explicitly
held the line here: **nothing gets deleted this pass.**

ADR-083 is corrected via a new ADR rather than an edit-in-place, matching
this campaign's own established practice for correcting a prior ADR's
factual claims (this is the third instance — ADR-085's premise, ADR-052's
note, now this): **`docs/adr-086-cli-authorize-stubs-stay.md`**. It
records:

- ADR-083's evidence table correctly traced `AuthorizePrincipal` (the
  HTTP/gRPC-middleware entry point) and correctly found
  `GetUserRoleIDsAt`/`GetUserGroupRoleIDsAt`/`RoleSetHasPermission` dead
  *through that entry point*.
- It did not examine `core.Authorize` — a second, independent entry point
  into the identical stub chain, called directly (no router, no
  middleware) by four CLI commands under `storage.type: remote`:
  `invite send`, `request list`, `request review`,
  `migrate user-to-machine` (traced in Wave 0; confirmed live in Wave 0b's
  sweep, which additionally found the same chain breaks `invite
  resend/revoke` and the whole `user` account-lifecycle family — 11
  commands total, filed as #1575).
- **Decision: keep these three methods as unconditional stubs.**
  Implementing them over the wire would have the CLI fetch role/permission
  data from the hub and decide authorization locally — the fat-client
  pattern this campaign has spent multiple rounds dismantling elsewhere.
  The correct fix is hub-side authorization (Wave 2, tracked by #1575,
  unified with #1546/#1551/#1572).
- Names the recurring mechanism explicitly, per the standing instruction:
  an ADR records intent at a point in time; a later reader treats it as
  verification of present-tense fact. The fix isn't "write more careful
  ADRs" — it's treating an ADR's factual claims the same way as any other
  code claim: re-verify before relying on them for a NEW decision (like a
  deletion), don't assume they're still true because they were once
  correct and no one flagged otherwise.

## Task 4 (Wave 0c) — handed to Wave 1, not fixed here

Two items filed/commented, not fixed, per the explicit instruction:

1. **The completeness guard's regex blind spot.** 13 raw
   `fmt.Errorf("not supported in remote storage")` stubs bypass
   `TestRemoteUnsupportedStubsAreAllowlisted`'s regex entirely (it only
   matches the `remoteUnsupported("MethodName")` call shape) — the guard is
   green while 13 members of the population it exists to cover are
   invisible to it. Same theme as #1540/#1541/#1547 (a guard that doesn't
   cover what its name implies). **Filed as
   [#1576](https://github.com/keyorixhq/keyorix/issues/1576)**, noting the
   exact count (13) and the regex gap
   (`remoteUnsupported\("([A-Za-z0-9_]+)"\)` never matches
   `fmt.Errorf("not supported in remote storage")`).
2. **#1511's list is partly stale.** `UpdateRiskException` was already
   fixed by a prior G79 round (`server/http/handlers/risk_exceptions_proxy.go:175-186`
   documents "a repo-wide search found no caller of it anywhere, local or
   remote" and the route was deliberately removed) and is still listed in
   `knownMissingRoutes`. **Commented on #1511** noting this and that
   whatever process produced the list was not re-run for this pass, so the
   remaining 12 entries were re-verified directly against source rather
   than trusting the list's currency.

## Task 5 (Wave 0c) — closed what the partition settled

- **#1512 closed.** `IsProjectMember` is not live — both plausible call
  chains (`share create`, `secret bulk-delete`) sit behind the
  `NewRemoteClient()` guard, re-confirmed against the complete idiom set
  (Task 1, Wave 0c above). Closing comment corrects the issue's own
  premise explicitly and notes the existing
  `GET /api/v1/system/project-memberships/active` route for a future
  Wave 2 defense-in-depth implementation, if wanted.
- **#1511 status:** not closed. 13 of 13 methods are now DEAD-flavored
  (Task 2, Wave 0c-corrected table above), but the deletion that would
  actually close it is explicitly held (Task 3, Wave 0c above) pending
  partition review. Commented with the stale-entry note (Task 4 above);
  left open with the residue named — the deletion pass itself.

Numbers don't need to sum to a clean 26 or 88 — this report's point is
that neither of those totals was the right frame to begin with; the
partition above is the actual current state.
