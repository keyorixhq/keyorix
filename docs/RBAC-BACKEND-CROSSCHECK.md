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

- [ ] Checked

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

- [ ] Checked

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

- [ ] Checked — **highest priority of this list**

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

- [ ] Checked

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

- [ ] Checked

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
