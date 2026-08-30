# ADR-083: `storage.type: remote` is a CLI/client mode only

## Status

**Accepted.** Supersedes the "full downstream Keyorix server" framing that
had informally grown up around ADR-049 in later code comments (`server/http/
router.go`, `internal/storage/store/remote_rbac.go`, `docs/
REMOTE_CLI_SETUP.md`) — ADR-049 itself never made that claim; see its own
Status header for the explicit correction. This ADR gates the topology at
config-validation time. Full removal of the topology's now-dead-weight code
(route registrations, the `/system` proxy tier's server-side half, the CLI
factory itself remaining valid for its actual use) is explicitly **deferred**
to its own branch — see "Deferred work" below.

**Partially corrected by ADR-086 (2026-08-28).** This ADR's evidence table
traced `AuthorizePrincipal` (the HTTP/gRPC-middleware entry point) and
correctly found `GetUserRoleIDsAt`/`GetUserGroupRoleIDsAt`/
`RoleSetHasPermission` dead through it. It did not examine `core.Authorize`
— a second, independent entry point into the same stub chain, called
directly (no router, no middleware) by several CLI commands under
`storage.type: remote`. Those three methods are therefore NOT part of the
"Deferred work" cleanup surface below — see ADR-086
(`docs/adr-086-cli-authorize-stubs-stay.md`) for the full evidence and
decision. The rest of this ADR (the topology gate itself, and the
route-registration/proxy-tier cleanup surface) is unaffected.

**Deferred removal done (#1480, 2026-08-30).** By the time this pass ran,
four prior deletion passes (the G80 158-method classification, its own
154-method deletion, #1596's 9-handler MFA/purge sweep, #1603's 3-proxy
stale-fork sweep) had already reduced this ADR's original "Deferred work"
list to almost nothing — the enumerated surface below (route registrations,
the `/system` proxy tier's server-side half, the ~18 `remote_storage_*_test.go`
files) was already gone or already reclassified as CLI-serving coverage, not
dead-topology coverage. What remained: **9 `RemoteStorage` client methods**
across 3 unrelated clusters, whose only real caller, repo-wide, was their own
now-removed `/system` server-side proxy handler — confirmed via the same
criterion ADR-087 established (trace every `internal/core` caller; a method
with zero core-layer callers and a route that no longer exists is dead,
because no `storage.type: remote` process can ever reach it as a server, and
no CLI command that reaches `internal/core` can reach it as a client either).
Deleted: `GetConnectorProjectBinding`/`CreateConnectorProjectBinding`
(ADR-082 branch 2's boot-time connector resolution — the resolving caller,
`server/main.go`'s `resolveConnectorOwnership`, calls `storage.Storage`
directly against whatever backend the server itself is configured with,
never `RemoteStorage`, since this ADR's own gate forecloses that);
`GetProjectByName` (same boot-time caller, same reasoning);
`TryAcquireSchedulerLock`/`ReleaseSchedulerLock`/`WithSchedulerLock` (#530 —
every scheduler tick runs against the server's own real backend, never
`RemoteStorage`, for the identical reason); `ListGlobalAdminAssignmentsForUpdate`
(dead since #525's `RemoveGlobalAdminRoleGuarded` atomic rewrite);
`ListSecretDependenciesForProjectForUpdate` (dead since #260's
`CreateSecretDependencyExclusive` atomic rewrite); `DeleteMFAStepUpGrantsFor`
(never had an `internal/core` caller — grants are reaped by TTL via
`PruneMFAStepUpGrants` instead). All 9 converted to `remoteUnsupported(...)`
stubs (not silently removed from the interface — `storage.Storage` is
unchanged) with a `remoteReachabilityRegistry`/`remoteUnsupportedAllowlist`
entry each, citing this evidence. Their 8 now-dead `/system` route
registrations and server-side handler functions were deleted outright
(`scheduler_lock_proxy.go` and `connector_project_bindings_proxy.go` deleted
in full; the other 4 handler functions removed from their otherwise-live
multi-handler files). **Explicitly untouched, on the same trace**: the 7 LIVE
`RemoteStorage` methods and 7 UNRESOLVED methods ADR-087/Wave 0 already
classified (kept means kept — no new evidence resolved any of the 7 this
pass), `validateRemoteStorageNotServer` itself and its test suite (enforcement,
not the topology it forbids — see its own doc comment, added this pass, for
why it must never be deleted alongside the topology), and everything the
CLI's embedded `storage.type: remote` path touches (verified directly: a real
`keyorix group create`/`group list` round trip against a live hub, through
the genuinely-unguarded embedded `RemoteStorage`-backed `core.KeyorixCore`
path — not the `NewRemoteClient()`/`ResolveRemote()` client-mode passthrough
most CRUD commands use — succeeded end to end post-deletion). Net: 39 files
changed, ~1,800 net lines removed. Full per-method citations:
`internal/storage/store/remote_reachability_registry_test.go`'s 9 new
`reachabilityDead` entries and the corresponding `remoteUnsupportedAllowlist`
entries (`remote_connector_project_bindings_completeness_test.go`,
`remote_rbac_completeness_test.go`, `remote_mfa_stepup_completeness_test.go`,
`remote_scheduler_lock_completeness_test.go`,
`remote_secret_dependencies_completeness_test.go`).

## Context

ADR-082 branch 4 (`connect.platform.use`) added a new `AuthorizePrincipal`
call to Keyorix Connect's platform-scope read path. Two new integration
tests exercising that call against a real `storage.type: remote` downstream
(`server/http/remote_storage_connect_grants_test.go`) failed —
`connect ownership: check connect.platform.use: not supported in remote
storage` — for both a user actor and a machine actor. Investigating why
uncovered a platform-level gap, not a Connect-specific one.

### Evidence

`AuthorizePrincipal` (`internal/core/authz.go:189`) is the general-purpose
RBAC entry point every `RequirePermission`/`RequireScopedPermission`-gated
HTTP route and gRPC RPC uses — not something specific to Connect. Traced in
full, both actor paths:

- **User**: `Authorize` → `scopedRoleIDs` → `storage.GetUserRoleIDsAt` +
  `storage.GetUserGroupRoleIDsAt` → (if any roles resolved)
  `roleSetContainsAdmin` (4× `storage.GetRoleByName`) →
  `storage.RoleSetHasPermission`.
- **Machine**: `storage.GetMachineRoleIDsAt` → `storage.RoleSetHasPermission`.

`RemoteStorage`'s actual implementation of each, read directly:

| Method | Status |
|---|---|
| `GetUserRoleIDsAt` | Hard stub — `return nil, fmt.Errorf("not supported in remote storage")` |
| `GetUserGroupRoleIDsAt` | Hard stub, same shape |
| `GetRoleByName` | Genuinely proxied (real HTTP call) |
| `GetMachineRoleIDsAt` | Genuinely proxied (real HTTP call) |
| `RoleSetHasPermission` | Hard stub — **both** actor paths depend on it |

The user path fails immediately at `GetUserRoleIDsAt`. The machine path gets
further (its role-ID lookup is real) but dies at the same final
`RoleSetHasPermission` stub. **`AuthorizePrincipal` cannot complete against a
`storage.type: remote`-backed `core.KeyorixCore`, for any permission, for
any actor.** This is not new, and not something ADR-082 branch 4 introduced
— branch 4 was simply the first thing to make Connect's platform-scope path
exercise a call this topology could never satisfy. `RequirePermission`
gates nearly the entire HTTP/gRPC API surface (project/secret/role/user
management, Connect, etc.) the same way — the gap is general, not local to
one route.

Confirmed via topology tracing, not assumed: `server/main.go` registers the
full router/gRPC server unconditionally on `server.http.enabled`/
`server.grpc.enabled`, with no branch on `storage.Type` anywhere in that
path. The one genuinely-working, storage-independent authorization
mechanism found — `RequireNodeCredentialOrPermission`'s `isNodeCredential`
check, gating the `/system` server-to-server proxy tier — is deliberately
**not** used by ordinary routes like Connect's `/connect/{name}/secret`
(confirmed directly in `router.go`, whose own comment draws this exact
line: that group is "the RemoteStorage server-to-server proxy API (machine
credentials only, system.write-gated)... these are human-facing reads"
elsewhere). No existing test — including every `#527`
`remote_storage_*_test.go` file and the two new branch-4 tests that
surfaced this — exercises a real HTTP router on a `RemoteStorage`-backed
core; every one of them calls core/storage methods directly, in-process,
bypassing `RequirePermission` entirely. Nothing has ever verified this
topology serves a real authorized request.

### This is a broken feature, not a vulnerability

Traced the error handling at every layer, HTTP and gRPC, both actor paths:
the stub's error is propagated verbatim at each step (`scopedRoleIDs` →
`Authorize` → `AuthorizePrincipal` → `finishScopedPermissionRequest`/
`authorizeScoped`), never swallowed, logged-and-continued, or converted to
an empty role set that falls through to a permissive default. HTTP maps it
to `403 Insufficient permissions`; gRPC maps it to
`codes.PermissionDenied`. **Fails closed at every layer, both transports.**
Every request to every gated route on a `storage.type: remote` server
errors or 403s — this has always been a broken feature (nothing works),
not a fail-open vulnerability (nothing was ever incorrectly allowed). No
separate security disclosure is warranted for previously-published releases
on this basis.

### Who is actually affected

Every consumer of `RemoteStorage` in the tree was checked:

| Consumer | Serves HTTP/gRPC routes on a `RemoteStorage`-backed core? |
|---|---|
| `server/main.go` (the server binary) | **Yes — unconditionally, whenever `storage.type: remote` + a server is enabled** |
| CLI (`internal/cli/modes.go`'s client mode, `internal/cli/common.InitializeCoreService`) | No — one-shot commands calling core methods directly in-process, no router/gRPC server ever constructed |
| `operator/` (k8s controller, separate module) | No `RemoteStorage`/`core.KeyorixCore` references at all |
| Helm charts, `docker-compose.yml`, `configs/*.yaml.tpl` | None demonstrate `storage.type: remote` at all |
| Existing tests (12 files reference `storage.type: "remote"`) | None also enable `Server.HTTP`/`Server.GRPC` |

Only `server/main.go`'s own boot path is affected. The CLI's actual,
working use of `storage.type: remote` — the entire reason this storage type
exists — is untouched.

## Decision

**`storage.type: remote` is a CLI/client mode only.** A process with
`server.http.enabled` or `server.grpc.enabled` **cannot boot** on it —
`Config.Validate()` (`internal/config/config.go`) rejects the combination,
in the existing `case "remote":` branch, via a new extracted function,
`validateRemoteStorageNotServer`, mirroring `validateConnectScopes`'s
pattern from ADR-082 §C (a `Config.Validate()`-time, boot-fail-loud check,
no deployment-wide bypass). The error message states plainly that remote
storage is a CLI/client mode and cannot back a server that serves API
routes, and points here.

## Rationale

- **No customer requested this topology.** It was never a delivered,
  requested capability — it grew from an informal assumption layered onto
  ADR-049's actual (narrower, CLI-only) decision, in code comments, over
  time, without ever being verified end-to-end.
- **It contradicts Keyorix's own deployment model.** A server that
  delegates its ENTIRE storage backend to an upstream server over HTTP is
  the opposite of the self-contained, air-gap-capable deployment story
  Keyorix is built around (ADR-062 and others) — a "downstream server"
  topology would mean a customer's secret-serving node depends on live
  network reachability to a separate Keyorix instance for every RBAC
  decision, the exact dependency air-gapped/on-prem deployments exist to
  avoid.
- **Gating first, not deleting, is deliberate.** Removing the topology's
  now-provably-dead code (see below) is a larger, separate change; gating
  it closes the actual risk (an operator accidentally believing this
  combination works) immediately, without deleting code under the time
  pressure of this investigation.

## Deferred work — done (#1480, 2026-08-30)

Originally, full removal of the `storage.type: remote`-as-server topology's
now-dead code was **out of scope for this ADR** and deferred to its own
branch. By the time that branch ran, four prior deletion passes (see "Deferred
removal done" in the Status section above) had already closed almost
everything this section originally listed:

- ~~The route registrations and `/system` proxy tier's server-side
  plumbing~~ — closed. The specific list this ADR named (login/MFA/WebAuthn
  proxy-verification, machine-identity role lookups, project/environment
  catalog, login-attempt counters) was already gone by #1596/#1603; only
  `ConnectRefGrant`/`ConnectorProjectBinding` CRUD's read/create half and the
  scheduler-lock/`ForUpdate`-snapshot pair this ADR didn't specifically name
  remained, and #1480 closed those.
- ~~The ~18 `server/http/remote_storage_*_test.go` files~~ — resolved by NOT
  removing them: they test the CLI's own genuine use of these primitives (the
  live/unresolved surface), which is exactly the coverage worth keeping, per
  this section's own original reasoning. Only the specific test functions
  covering the 9 methods actually deleted were removed.
- ~~Whether ADR-082 branch 2's `0a4194ce`
  (`ConnectorProjectBinding` storage-primitive commit) becomes unnecessary~~
  — resolved: its `Get`/`Create` methods (the boot-time connector-resolution
  half) were dead and are now stubs; `ListConnectorProjectBindings` was
  already a stub (Wave 0). The model/interface declarations are unchanged —
  `LocalStorage`'s real implementation is the live one, used by the resolving
  server's own boot path, per this ADR's own "Who is actually affected"
  table.

The gate in `Config.Validate()` remains the durable enforcement — see its own
doc comment (`internal/config/config.go`), which now states explicitly that
it must survive any future cleanup pass, including this one.

## Consequences

**Positive.** Closes an operator-facing trap: a `storage.type: remote` +
`server.http.enabled: true` config now fails loud at boot, instead of
starting a server that silently 403s every request. No previously-published
release needs a security disclosure (fail-closed, confirmed above).

**Negative.** Any config genuinely relying on this combination — evidence
found none in the tree, and it could never have served a real authorized
request — will now fail to boot instead of starting into a broken state.
This is the intended effect: fail at boot, loudly, rather than fail per
request, silently (from the operator's perspective — "why does every API
call 403").
