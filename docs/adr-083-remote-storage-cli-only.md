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

## Deferred work

Full removal of the `storage.type: remote`-as-server topology's now-dead
code is **out of scope for this ADR** and deferred to its own branch:

- The route registrations and `/system` proxy tier's server-side plumbing
  that exist specifically to let a "downstream" node proxy through to an
  upstream (login/MFA/WebAuthn proxy-verification, machine-identity role
  lookups, `ConnectRefGrant`/`ConnectorProjectBinding` CRUD, project/
  environment catalog, login-attempt counters, etc.) — all built under the
  assumption a full downstream server was a real, reachable target.
- The ~18 `server/http/remote_storage_*_test.go` files, which test that
  proxying machinery in isolation (in-process, bypassing `RequirePermission`
  entirely, per the Evidence section above) — worth keeping as coverage for
  the CLI's own use of these primitives, but their framing/naming should be
  revisited once it's clear they were never proving a working server
  topology.
- Whether ADR-082 branch 2's `0a4194ce` (the `ConnectorProjectBinding`
  RemoteStorage storage-primitive commit, built to let Connect ownership
  resolution proxy correctly on a "downstream" node) becomes unnecessary
  work, given that topology never functioned as a server in the first
  place — needs its own assessment, not decided here.

None of this is committed to in this ADR. The gate in `Config.Validate()`
is the only enforcement change; everything else stays as-is, reachable only
by the CLI's actual (correct, unaffected) use of `storage.type: remote`,
until the deferred branch addresses it.

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
