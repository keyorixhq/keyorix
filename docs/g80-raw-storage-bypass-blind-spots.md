# Raw-storage-bypass guard — named blind spots

Companion to `docs/g80-raw-storage-bypass-enumeration.md`. Same treatment as
`knownUnresolvedWireCalls` in `internal/storage/store/remote_wire_route_coverage_test.go`:
name what the tool structurally cannot see, so it reads as an enumerated backlog rather
than a silent "covered everything" claim. **Not investigated further tonight** — per
the overnight brief, these are listed, not chased. Fix trivial ones now (one is), list
the rest.

## (a) Multi-line method chains — FIXED, not a blind spot for the AST tool

`scripts/analysis/raw_storage_bypass_enumerate.go` parses real Go syntax trees
(`go/ast`), which have no concept of line breaks — `h.coreService.\n\tStorage().\n\tX(...)`
and `h.coreService.Storage().X(...)` produce identical ASTs. This was the leading
hypothesis for the 149-vs-145 discrepancy; grepping for every line ending in
`coreService.`, `Storage()`, or `c.storage.` across `server/http/handlers` and
`internal/core` found zero non-test matches, and the AST tool's result (145/58) matches
the regex tool's result (145/58) exactly — confirming line-wrapping was never the cause.
**Only the original regex-based `raw_storage_bypass_guard_test.go` (scoped to the
18-route `classifiedNodeCredentialRoutes`) would still have this blind spot** if it were
ever extended repo-wide without also being rewritten to use AST; the standalone
enumeration script does not have it.

## (b) Variable/interface dispatch — partially fixed, evidence: 0 current instances

The enumeration script tracks simple local aliases: `alias := x.Storage()` followed by
`alias.Method(...)` in the same function body (see the `[via local alias]` annotation
in the tool's output — none appear in today's 58, i.e. this pattern is not currently
used anywhere in `server/http/handlers`). What it does **not** track:

- An alias bound in one statement and used across a closure boundary (e.g. inside a
  goroutine or a deferred func literal within the same handler) — untested, no known
  instance.
- A `storage.Storage` value stored on a struct field at construction time (e.g. a
  handler type embedding a `storage storage.Storage` field set once in a constructor,
  rather than calling `h.coreService.Storage()` fresh per-request) — checked, no handler
  struct in `server/http/handlers` currently does this (all route through
  `h.coreService.Storage()`), but the tool has no defense against it if one is added.
- Dispatch through an interface value passed as a function parameter into a shared
  helper (e.g. `func doWrite(s storage.Storage, ...)`  called from multiple handlers) —
  no known instance, not checked exhaustively.

## (c) Wrapper-mediated calls (the `putConditionalTransition` shape) — REAL, currently present

Confirmed, not hypothetical: `checkBreakGlassRoleContainment`
(`server/http/handlers/break_glass_proxy.go:139-157`), a private helper called by both
`CreateBreakGlassActivationProxy` and `UpdateBreakGlassActivationProxy`, itself makes two
raw `h.coreService.Storage().{GetRoleByName,RoleSetHasPermission}(...)` calls. The
enumeration script only walks the exported handler's *own* function body — a call inside
a helper the handler invokes is invisible to it, exactly the shape
`knownUnresolvedWireCalls` already names for `entry.go`'s `putConditionalTransition`
(one wrapper definition, checked once, with callers resolved separately) — except here
there is no equivalent "resolve each caller separately" mechanism at all; the helper's
calls are just not examined by anything. In this specific instance the two calls
(`GetRoleByName`, read-shaped; `RoleSetHasPermission`, not currently in the `wrapped` set)
don't add to today's 58, but the mechanism means a future helper that DOES call a
wrapped write method would go completely unseen. No exhaustive search was run for other
instances of this shape (helpers matching the `func (h *XHandler) unexported(...)`
pattern number in the dozens across the handlers package — see the 34-item list from the
initial signature sweep this session ran, e.g. `rbac.go`'s
`authorizeAndCollectPermissions`/`replaceRolePermissions`, `dynamic_secrets.go`'s
`authorize` — none individually checked for this pattern beyond the one confirmed
example above).

## (d) The read-shaped naming heuristic — REAL, evidence in both directions

The `Get*`/`List*`/`Count*`/`Export*` exclusion is a pure prefix match on the method
name, not a semantic check of what the method does. Checked the full `LocalStorage`
interface (414 exported methods) for evidence in both failure directions:

- **Dangerous direction** (a writer that LOOKS like a read and gets wrongly excluded,
  e.g. `GetOrCreateX`, `EnsureX`, `ResolveX`): **zero instances found** in the current
  interface. This does not mean the heuristic is safe — it means the codebase hasn't
  happened to add one yet. The tool has no defense if it does.
- **Safe-but-still-wrong direction** (a genuine reader that ISN'T excluded, inflating the
  write-shaped count with false positives): confirmed instances —
  `IsProjectMember`, `IsGroupProjectScoped`, `HasActiveMFAStepup`,
  `HasUnreadNotification` — none of which start with Get/List/Count/Export despite being
  pure boolean reads. None of these four currently appear in the write-shaped 58 (spot
  checked against the committed list), so today's count isn't inflated by this, but the
  heuristic would misclassify any of them the moment a handler calls one directly via a
  wrapped core method.

## (e) Non-handler layers — REAL, entirely out of scope by construction, substantial

The guard (both the original 18-route version and this session's repo-wide extension)
only examines `server/http/handlers`. It does not examine:

- **gRPC services** (`server/grpc/services/`) — 7 files make raw `.Storage()` calls.
- **CLI commands** (`internal/cli/*/`) — 13 files make raw `.Storage()` calls (this is
  the embedded/local-storage CLI path, not the RemoteStorage relay path this whole bug
  class is about, but any of these commands COULD be run against a `storage.type: remote`
  backend per ADR-083/#1512's discussion elsewhere in this campcampaign, at which point
  the same bypass shape would apply).
- **Background jobs / schedulers** — not inventoried this session at all (no file count
  taken); flagged as unexamined, not as empty.

20 files total (7 + 13) make raw storage calls entirely outside this guard's field of
view. No claim is made about how many of those raw calls bypass a real ceiling — that
would require the same per-candidate triage this session did for the HTTP-handler layer,
scaled to three more code layers, which is explicitly out of scope for tonight per the
brief ("Do NOT investigate the blind spots tonight").

## (f) Other route groups within server/http/handlers — REAL, concretely evidenced

Distinct from (e): this is not about a different code LAYER (gRPC, CLI, jobs), it's about
other route GROUPS within the same `server/http` router that this guard's own scope
(`/api/v1/system`) never looks at. Discovered as a byproduct of resolving the 58-vs-57
discrepancy when the guard was made blocking: `ConsumeMFAChallenge`
(`server/http/handlers/users_crud.go:710`) is registered at `router.go:874` under
`RequirePermission(permUsersWrite)` — a completely different route group, gated by
`users.write`, not `system.write` and not `/system` at all — yet it exhibits the exact
same shape this guard exists to catch (a handler calling `Storage().ConsumeMFAChallenge(...)`
directly where an exported core method also wraps that primitive). It was individually
triaged and resolved safe (`documented-exception` — see `docs/g80-raw-storage-bypass-triage.md`),
so it isn't itself a live finding, but its EXISTENCE is the evidence for this category:
the raw-storage-bypass shape is not unique to the `/system` proxy tree. `server/http/handlers`
has many route groups beyond `/system` (project-scoped human-facing routes, `/scim/v2`,
admin-only routes, etc.) that this guard has never scanned even once, at any point in this
campaign (#1542's original 18-route version, tonight's repo-wide-within-/system extension,
or the now-blocking guard). Not scanned tonight, per instruction — named as a concrete,
evidenced gap, not a hypothetical one.

## Summary

**Stated reach**: 57 write-shaped candidates within the `/api/v1/system` route group
(`server/http/handlers`), all individually triaged (`docs/g80-raw-storage-bypass-triage.md`).
The reconstruction actually found 58 handler-level candidates repo-wide; one
(`ConsumeMFAChallenge`) turned out to sit outside `/system` entirely under a different
permission group (`users.write`) — see category (f) above, added after that correction.
**Six categories unexamined or partially examined**, one fixed (a, via AST), one
mostly-empty-but-unguarded (b), four real and open (c, d, e, f). The number in the
handoff doc should be read as "35 of 57 real,
human-reachable, **within the guard's stated reach**" — not as a claim about the total
size of this bug class across the codebase.
