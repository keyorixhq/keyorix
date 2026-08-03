# RBAC server-side enforcement cross-check

Working checklist from the Phase 0 audit (`docs/PHASE0-AUDIT-FINDINGS.md`,
"Client-side authorization theater" section) — every item the frontend audit
flagged as "the client can't verify this, someone needs to check the backend."
Since it's the same person on both sides now, this is the concrete list of
what to go confirm in the Go repo, with the exact endpoint each item hits.

For each: open the corresponding Go handler, confirm the authorization check
described, then check it off. If a check is missing, it's a real
privilege-escalation bug (not just a client-side UX gap) — fix it in the
backend, not by adding a client-side guess here.

---

## 1. Project membership mutations — `ProjectMembersTab.tsx`

**Frontend behavior**: the add-member, role-change, and remove-member controls
have **zero** client-side role gating today (every project member sees them,
unlike the sibling `MachineIdentitiesSection` in the same tab, which does check
`isAdmin`). The entire trust boundary is server-side, with no client hint
either way.

**Endpoints** (`src/services/projects.ts:341,345,349`):
- `POST /api/v1/projects/:id/members` — add member (`{user_id, role}`)
- `PUT /api/v1/projects/:id/members/:userId` — change role (`{role}`)
- `DELETE /api/v1/projects/:id/members/:userId` — remove member

**Confirm**: each of these three independently checks that the *caller* holds
a project-admin-equivalent role **in that specific project** (not just "is
authenticated" or "is a global admin") before mutating. Also confirm: can a
project member add/promote *themselves* to a higher role than they hold? Can a
non-member (not on the project at all) hit these by guessing a project ID?

- [x] Checked (2026-07-04) — All three routed through `RequireScopedPermission("roles.assign", <project scope>)`
  (`server/http/router.go:340-342`) into `server/http/handlers/project_members.go`. Non-members are rejected by
  the middleware before the handler runs (zero roles in that project scope → 403); `RemoveProjectMember` additionally
  double-checks membership explicitly. Self-escalation is blocked by `requireGranterHoldsRolePermissions`
  (`internal/core/authz.go`), which requires the granter to already hold every permission in the role being
  assigned — can't grant yourself a role with more permissions than you have. `guardLastProjectAdmin`
  (`internal/core/project_members.go`) additionally blocks removing/demoting a project's last `roles.assign` holder.
  Sufficient, no gap.

## 2. Built-in role deletion — `RolesPoliciesPage.tsx`

**Frontend behavior**: the "delete role" button is `disabled={builtIn}`, where
`builtIn` is a pure client-side name match against `BUILT_IN_ROLES`
(`src/types/rbac.ts`) — the client never consults a server-echoed "is this
built-in" signal.

**Endpoint** (`src/services/rbac.ts:58`): `DELETE /api/v1/roles/:id`

**Confirm**: the handler independently rejects deletion of built-in roles *by
ID*, not just by name (i.e., can't be bypassed by creating a custom role that
happens to share a built-in role's name, or by hitting the endpoint directly
with a built-in role's numeric ID via curl/devtools).

- [x] Checked (2026-07-04) — `server/http/handlers/rbac.go:345-348` fetches the role by ID first, then checks the
  fetched row's `Name` against `core.IsBuiltinRole()` (`internal/core/auth_bootstrap.go`'s `builtinRoleNames` map)
  and returns 403 if built-in. Same name-based approach as the frontend (no dedicated `is_builtin` column), but
  not exploitable: `Role.Name` has a DB-level UNIQUE constraint, so a custom role can't be created sharing a
  built-in name to game the check, and hitting the endpoint directly with a built-in role's real numeric ID still
  triggers the name check after the DB fetch. Both HTTP and gRPC role-delete paths share this check. Sufficient,
  no gap — the shared reliance on names-not-flags is a minor structural nit, not a bypass.

## 3. Personal Access Token scope intersection — `ProfilePage.tsx`

**Frontend behavior**: PAT creation lets the user type an arbitrary
comma-separated `extraPermissions` free-text field
(`buildCreateTokenBody`, `src/services/personalTokens.ts:34-72`), sent
verbatim as `scopes` in the request body. The client only dedupes/trims — it
never checks the requested strings are actually a subset of the caller's own
current permissions.

**Endpoint** (`src/services/personalTokens.ts:91`): `POST /api/v1/auth/tokens`
body includes `scopes`, `project_scope`, `environment_scope`.

**Confirm**: the handler intersects the requested `scopes` (and
project/environment scope) against the caller's **live, current** permission
set server-side, rather than trusting the submitted list at face value. This
is the highest-severity item on this list — it's the one place the client
sends arbitrary "permission" strings rather than just a boolean UI gate, so a
missing check here is a direct privilege-escalation path (mint a token with
more scope than the creating user actually has), not just a UX gap.

- [x] Checked (2026-07-04) — **No creation-time subset check exists** (`internal/core/pat.go`'s `CreateOwnPAT`
  only dedupes/validates format, never checks against the caller's permissions), **but this is deliberate, not a
  gap** — see `docs/adr-042-pat-permission-scoping.md`: over-broad requested scopes are inert because every
  request-time authorization check runs the scopes through `PATRestriction.Allows()`
  (`internal/core/authz.go:75-102`), which denies anything outside BOTH the token's stored restriction AND the
  caller's actual current roles — checked BEFORE role resolution, and PAT restrictions are re-fetched fresh from
  the DB on every request (not cached), so a leaked/over-scoped token can be narrowed retroactively too. Proven by
  `internal/core/pat_scoping_e2e_test.go`. Not a privilege-escalation path — the runtime intersection, not
  creation-time validation, is the actual security boundary. No gap.

## 4. Self-action guards (suspend/reactivate/force-logout/etc.) — `UserDetailPage.tsx`

**Frontend behavior**: "Account actions" (Suspend, Reactivate, Force password
reset, Force log out, Convert to machine identity) are hidden when
`isSelf = currentUser?.id === user.id`, purely client-side.

**Endpoints** (`src/services/users.ts:148-169`):
- `POST /api/v1/users/:id/suspend`
- `POST /api/v1/users/:id/reactivate`
- `POST /api/v1/users/:id/unlock`
- `POST /api/v1/users/:id/require-password-reset`
- `POST /api/v1/users/:id/revoke-sessions`

**Confirm**: does the backend reject (or intentionally allow?) an admin
targeting their own `id` on these. Severity is low regardless — worst case is
self-inflicted lockout/DoS, not privilege escalation — but worth a deliberate
answer either way (block it, or accept it as an intentional "admin can suspend
themselves" allowance) rather than an accidental gap.

- [x] Checked (2026-07-04) — Suspend/Reactivate/RequirePasswordReset (all via the shared `accountStateAction`
  helper, `server/http/handlers/users_crud.go:370`) and RevokeSessions (`users_crud.go:416`, fixed this session)
  all reject self-targeting with 400. There's a 6th sibling in this family not in the original frontend list —
  **`unlock`** (`POST /api/v1/users/:id/unlock`, clears login-lockout state) — which has no self-action guard.
  Decided this is fine as-is, not a bug: unlike the other four, `unlock` only *clears* a restriction, so a
  self-targeted call is a harmless no-op (it can't create the self-inflicted lockout the guard on the other four
  exists to prevent). No fix needed. ("Force log out" in the frontend list maps to `revoke-sessions`.)

## 5. Stale cached permissions mid-session — `authStore.ts`

**Frontend behavior**: `refreshToken()` (`src/store/authStore.ts`) updates only
the token/expiry — never re-fetches `user.roles`/`user.permissions`. A
demoted/promoted user's client-side nav and permission-gated buttons stay
stale for the rest of their session (same root cause as the M1 finding, which
already got a client-side fix — this is the backend half of that same
finding).

**Confirm**: every mutating endpoint re-validates the caller's **current**
role/permission from the database on each request, rather than trusting
whatever claims were embedded in the token at issuance time. If this is
already true, the client-side staleness is harmless UI lag (the demoted user
*sees* stale admin affordances but any click still 403s) — if not, it's a real
privilege-persistence bug independent of anything the frontend can fix.

- [x] Checked (2026-07-04) — Confirmed harmless. The 30s token-validation cache (`server/middleware/auth.go`)
  stores a `UserContext.Roles` snapshot, but that field is never consulted for authorization (`RequireRole()` is
  the only reader and has no production callers). Every mutating endpoint's real check goes through
  `AuthorizePrincipal` → `Authorize` → `scopedRoleIDs` (`internal/core/authz.go`), which runs uncached GORM
  queries (`GetUserRoleIDsAt`/`GetUserGroupRoleIDsAt`) against the DB on every call. A demoted user's next
  mutating request is correctly re-checked against their new permissions regardless of what's cached on the
  token. Frontend staleness is cosmetic only — no gap.

## 6. Scoped-vs-global permission mismatch (separate, lower-priority item)

Not a "confirm the backend" item — this is a **missing capability**, not a
missing check. `MachineIdentitiesSection.tsx`, `DynamicSecretsPage.tsx`, and
`LeasesPanel.tsx` gate UI on the global `isAdmin` flag, but their own code
comments describe the real requirement as a project/config-scoped permission
(e.g. "`secrets.write` at the config's scope"). There is no
"my permissions in this project" endpoint today for the client to call
instead. If/when Phase 1 or later work wants to fix this properly, this is the
new endpoint that needs designing — not something to check off against
existing behavior.

- [ ] New endpoint designed (if/when prioritized) — not blocking, not urgent
