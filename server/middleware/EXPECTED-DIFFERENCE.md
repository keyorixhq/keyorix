# CH1 EXPECTED-DIFFERENCE — chi routing vs. the authorization path

This is the committed disagreement-class table for the CH1 differential harness
(`chi_authz_route_differential_test.go`, `..._fuzz_test.go`). It is the prose
companion to `expectedDifferenceClasses` in
`chi_authz_route_expected_difference_test.go`; the Go map is the machine-checked
source of truth (a class not listed there fails the oracle), this file is the
rationale.

## What the harness compares

- **Primary oracle (CH1-A / CH1-B):** the restricted-PAT refusal decision made by
  the REAL `RefuseRestrictedPATUngatedWrites` middleware (which independently calls
  `routes.Find`) must match the refusal-status (`core.RestrictedPATWriteRefusal`) of
  the route chi **actually dispatches** to. This oracle has **no** expected
  differences — any disagreement is a real authorization-vs-routing divergence and
  fails unconditionally. It is not governed by the table below.
- **Differential oracle (CH1-C):** chi's dispatched `RoutePattern()` vs. an
  independent, strict, decoded-path segment matcher built from the same route table.
  The semantic gap between the two matchers is benign for *route selection* and is
  enumerated here. Only a class NOT listed fails.

## Why the two CH1-C matchers legitimately disagree

chi matches on the **escaped** path and treats `%2F` as an ordinary character inside
a single segment; it distinguishes trailing slashes and is case-sensitive; it does
not normalize `.`/`..`. The reference matcher instead **percent-decodes** the whole
path and splits on `/` with strict RFC-3986 generic-URI semantics. These are two
defensible readings of "which route does this path name"; where they differ, chi's
reading is authoritative (it is what runs) and the difference is one of the classes
below.

| Class | Meaning | Why benign for route selection |
|-------|---------|-------------------------------|
| `encoded-slash` | path contains `%2F` | chi keeps it literal inside one `{param}`; the decoded reference sees extra segments. The decoded value only ever reaches a handler/scope-resolver, never re-routes. The primary oracle still checks the refusal-status of whatever chi dispatched. |
| `percent-encoding` | other `%xx` present | reference decodes before splitting, chi matches escaped bytes; a literal segment can match on one side only. Non-match, never a cross-route match. |
| `double-slash` | `//` yields an empty segment | chi fails that segment against any literal/`{param}`; reference drops it. Divergence is a non-match on one side. |
| `dot-segment` | a `.` or `..` segment | neither chi nor the mux normalizes dot segments; reference treats them as literals. Divergence is a non-match, not a cross-route match. |
| `trailing-slash` | path ends with `/` | chi treats `/x` and `/x/` as distinct (no `RedirectSlashes` installed); reference likewise, but can disagree on a Route-root `/x/`. |
| `reference-ambiguous` | reference matched >1 same-method pattern, no encoding feature | overlap of a literal and a `{param}` route (e.g. `/secrets/export` vs `/secrets/{id}`). chi deterministically prefers the literal; the reference reports both. chi's choice is still a real registered route and the primary oracle checks its refusal-status. |

## Classes deliberately NOT expected (these FAIL)

- `chi-matched-reference-empty` — chi dispatched to a route the strict reference says
  nothing matches, and **no** encoding/slash/dot feature explains it. A structural
  surprise worth a hard look (could be a genuinely unexpected chi match).
- `chi-picks-different-route` — chi and the reference each matched a single, different
  concrete pattern, with no encoding feature to explain it. The strongest CH1-C
  signal: the same path names two different routes to the two matchers.

## What CH1 does NOT verify (honest limits)

- **Only the PAT-restriction gate is an independent route matcher.** All other HTTP
  authorization is per-route `r.With(...)` middleware, i.e. inside the matched
  route's own chain, so "authorized route == served route" holds by construction and
  is **not** fuzzed here — there is nothing to diverge.
- **The replica, not the live router.** Routes come from the committed inventory
  `scripts/e2e/routes.json`; handlers are recording stubs. chi routing depends only
  on the pattern set + mux options (no path-rewriting middleware exists in
  `NewRouter`), so dispatch is faithful, but this does not exercise real handler
  bodies, real auth, body limits, CSRF, or the full middleware stack.
- **Nested `r.Route` node structure.** The replica registers `/api/v1` patterns flat
  (which router.go itself largely does). A trailing-slash edge case arising *only*
  from chi's `r.Route` mount-root node shape (a `/x/` root) may not be reproduced.
- **CH1-C models exact-segment routes.** Mount subtrees (`/swagger/*`) are matched as
  catch-alls; `{param:regex}` constraints are not modeled (the route table has none).
- **The refusal table's correctness is assumed.** CH1 checks that the gate acts on the
  route chi serves; it does NOT re-derive whether each table entry *should* be refused
  (that is ADR-042 / the restricted-PAT persona guards' job).
- **No gRPC.** The sibling gRPC restricted-PAT interceptor
  (`server/grpc/interceptors/auth.go`) resolves methods by full RPC name, not by chi;
  it is out of scope for this chi-routing harness.
