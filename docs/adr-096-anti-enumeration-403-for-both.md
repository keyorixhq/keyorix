# ADR-096: Anti-enumeration status-code convention — 403-for-both, not 404-for-both

## Status

**Accepted (2026-09-01).** #1645. This ADR documents the decision and the
migration mechanism; see the tracking issue for which call sites have moved
onto it as of any given date — the decision is final, the migration is
incremental.

## Summary

#1645 found two incompatible, undocumented conventions coexisting for how a
scoped-resource endpoint (a secret, project, user, role, dynamic-secret
config, ...) responds when the caller either lacks the permission or the
resource doesn't exist:

- **Convention A (403-for-both)**: the primary GET-by-ID routes
  (`server/middleware/auth.go`'s `handleScopeResolutionError`, used by
  `RequireScopedPermission`/`RequireScopedSecretPermission`). An unauthorized
  caller gets an identical 403 whether the target exists or not; only a
  caller who holds the permission **globally** gets a real 404.
- **Convention B (404-for-both)**: a separate, independently-invented idiom
  (tagged `#G14`/`#G85`/`TMPL-002` at each site) used by dynamic-secret
  config/lease routes, SCIM provisioning collision checks, secret rename, and
  gRPC's `GetSecret`/dynamic-secret RPCs. Denied and nonexistent both
  collapse to a uniform 404, **regardless of caller privilege** — there is no
  privileged-caller exception at all in this convention.

**Decision: Convention A (403-for-both) is the house standard.** Convention B
sites migrate to it. Not because A is the majority (that would be a weak
reason to standardize — if B were the better design it would be worth the
larger migration the other direction) — because of the threat model.

## Why 403, not 404

404-for-denied is a deliberate lie to an authenticated user already inside
the trust boundary. That's a reasonable trade for a product like GitHub,
whose threat model is anonymous scraping of private repos. It is not a
reasonable trade for an on-prem secrets tool used during incidents: an
operator who lacks a permission and is told "not found" concludes the secret
was deleted, or that they're pointed at the wrong server. That misdirection
has a real operational cost, and it buys very little against an attacker who
is already authenticated and knows the route shape.

## The convention, precisely

Four conditions. Without all four, "pick 403" is not actually a convention —
it's a status code with no enforcement, which is exactly how this repo ended
up with two conventions the first time.

### 1. The real-404 exception is narrow, and must stay narrow

A genuine 404 (not the collapsed one) is returned **only** when the caller
holds, **at global scope**, the **same permission** that would have granted
access to this specific resource had it existed. Not "any global
permission." Not "global read on some other resource type." That sentence is
the whole exception — a looser version (e.g. "any authenticated caller with
some admin-tier role") re-opens the oracle for a broader population than
intended.

`handleScopeResolutionError` implements this exactly today:

```go
func handleScopeResolutionError(w http.ResponseWriter, r *http.Request, cs *core.KeyorixCore, userCtx *UserContext, permission string, err error) {
	if errors.Is(err, errTargetNotFound) {
		if ok, aerr := cs.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), permission, core.Scope{}); aerr == nil && ok {
			notFoundResponse(w, "Resource not found")
		} else {
			forbiddenResponse(w, "Insufficient permissions")
		}
		return
	}
	badRequestResponse(w, "Invalid target")
}
```

`core.Scope{}` here is the global scope — the check is literally "does this
caller hold `permission` with no project/environment restriction," which is
the precise exception, not an approximation of it.

### 2. The convention is the whole response, not just the status code

Identical body, identical error-code string, identical headers. Two handlers
both returning 403 with `{"error":"forbidden"}` vs
`{"error":"secret not found in project"}` leak exactly as much as
403-vs-404 did — the caller learns which case they hit either way. Every
site that adopts this convention must produce the SAME body shape
`handleScopeResolutionError`/`finishScopedPermissionRequest` already produce
for the "denied" branch (`forbiddenResponse(w, "Insufficient permissions")`)
— not a resource-specific message that happens to also be a 403.

### 3. Route through the shared mechanism, not a re-derived per-site check

`handleScopeResolutionError` already exists and is exercised by every
primary GET route today. The migration for a Convention-B site is "route
this resource's scope resolution through `RequireScopedPermission`/a new
`ScopeResolver`" — a mechanism fix, not writing the collapse logic again at
each call site. See "Migration mechanism" below for the concrete shape.

### 4. gRPC is specified here too, not left to be re-derived later

`secret_service.go`'s `GetSecret` is one of the divergent (Convention B)
sites, and gRPC has its own status codes (`PermissionDenied` vs `NotFound`,
not HTTP 403/404). A convention written only in HTTP terms leaves gRPC to
reinvent its own version later — which is how this repo ended up with two
conventions the first time. The gRPC-side rule is the identical shape:

- Denied or nonexistent, caller lacks the permission globally →
  `codes.PermissionDenied`, with the same message text regardless of which
  case actually happened.
- Nonexistent, caller holds the permission globally → `codes.NotFound`.

A shared Go function analogous to `handleScopeResolutionError` (gRPC has no
middleware chain equivalent to chi's, so this is a plain function called
from each RPC handler, not middleware) should back every gRPC RPC that
resolves a scoped resource by ID, for the same "one mechanism, not
per-RPC copies" reason.

## Scope: this is a full rule, not just a GET-by-ID rule

Two gaps the original recon didn't cover, closed here so the convention is
complete:

- **List endpoints** already comply by construction: they return 200 with
  the filtered result set (an empty list leaks nothing — it's the honest
  answer for "you have access to zero matching items," indistinguishable
  from "zero items exist"). No change needed; noted so a future audit
  doesn't have to re-derive this.
- **Write verbs** (PUT/PATCH/DELETE) on a resource the caller can't see
  follow the identical 403-for-both rule as GET. A write route that
  resolves scope via `RequireScopedPermission`/`RequireScopedSecretPermission`
  already gets this for free (the middleware doesn't distinguish HTTP
  method). A write route with its own hand-rolled existence check (matching
  the shape #1645 found on the read side) needs the same migration as any
  other Convention-B site — otherwise existence gets probed through DELETE
  instead of GET, which defeats the point.

## Migration mechanism

For an HTTP handler currently doing its own fetch-then-authorize-then-collapse
(the `loadAuthorizedConfig`/`loadAuthorizedLease` shape in
`server/http/handlers/dynamic_secrets.go` is the clearest example): write a
`ScopeResolver` (`server/middleware/auth.go`'s existing type) for the
resource, matching `ScopeFromSecretParam`'s shape —

```go
func ScopeFromDynamicSecretConfigParam(param string) ScopeResolver {
	return func(r *http.Request, cs *core.KeyorixCore) (core.Scope, error) {
		id, err := scopePathUint(r, param)
		if err != nil {
			return core.Scope{}, errInvalidTarget
		}
		cfg, err := cs.GetDynamicSecretConfig(r.Context(), id)
		if err != nil {
			return core.Scope{}, errTargetNotFound
		}
		return core.Scope{ProjectID: cfg.ProjectID, EnvironmentID: cfg.EnvironmentID}, nil
	}
}
```

— then wire the route through `RequireScopedPermission(perm,
ScopeFromDynamicSecretConfigParam("id"))` in `router.go` instead of calling
the handler-internal loader, and delete the handler-internal
fetch/authorize/collapse logic (the handler now runs only once already
authorized, and can fetch the row again cheaply, or the middleware can stash
it on the request context the way `RequireScopedSecretRefPermission` already
does for the by-ref read path, if avoiding a second fetch matters for that
route).

Where full middleware conversion is impractical for a specific call site
(e.g. a check embedded in a larger multi-step operation like SCIM
provisioning's collision check), the same decision must still be made by ONE
shared, exported function callable from handler code — not re-derived
inline. `handleScopeResolutionError` itself is unexported (package
`server/middleware`); either export it or add a thin exported wrapper in
that package so handler packages can call the identical logic without a
full route restructure.

## Guard

An assertion that every handler touching a scoped resource returns denial
through the shared mechanism, not a hand-rolled status code, is required
once the migration lands — otherwise this drifts back to two conventions the
same way it happened the first time. `handleScopeResolutionError`/
`RequireScopedPermission` is the thing to grep for; a guard test enumerating
every route registered against a `{id}`-shaped scoped-resource path and
confirming it's wired through one of the shared resolvers (or is on an
explicit, individually-justified exception list, mirroring
`raw_storage_bypass_guard_test.go`'s own allowlist pattern) is the cheapest
way to enforce this going forward.

## Explicitly deferred: timing side-channel

If the exists-but-denied path does a real lookup and the doesn't-exist path
returns early (or vice versa), response time can distinguish the two cases
regardless of what status code and body are returned. Routing every site
through one shared mechanism helps structurally (a single code path means a
single timing profile, rather than N independently-timed implementations),
but actually measuring and closing that gap is a separate pass — not
attempted as part of this ADR or its migration.
