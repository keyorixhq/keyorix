# Phase 0 audit findings (keyorix-web pre-rewrite security audit)

Ran 2026-07-04, per `docs/SHADCN-REWRITE-PLAN.md` Phase 0. Four parallel agents,
one per vein; the two HIGH findings and one MEDIUM-HIGH finding were then
independently re-verified by a second, adversarial agent per vein (told to try to
*refute* the claim, not confirm it) before being trusted. All three were
**CONFIRMED**, two of them via live reproduction in a throwaway `nginx:alpine`
container against the repo's actual `nginx.conf`.

Severity/tag legend: **fix now** = survives the rewrite (auth, build/deploy,
feature/page code); **moot after rewrite** = lives only in one of the 11 UI
primitives being torn out in Phases 3-4 (none found this round).

---

## Confirmed HIGH severity — recommend fixing before/independent of the rewrite

**Status: FIXED 2026-07-04**, both in `nginx.conf`, verified live in a throwaway
`nginx:alpine` container (config passes `nginx -t`; response headers checked on
`/`, a static asset path, and `/api/foo` with a hostile `Origin`). H1 fix: removed
the CORS `add_header`s and the OPTIONS-preflight special case entirely — confirmed
via `git log`/repo search that no legitimate cross-origin browser caller of this
API exists (the SPA and API are same-origin through this same nginx, and CSP
already restricts `connect-src` to `'self'`), so there is nothing to allowlist.
H2 fix: repeated the 5 security headers (`X-Frame-Options`,
`X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`,
`Content-Security-Policy`) in every location block that defines its own
`add_header`, since nginx doesn't merge — confirmed all 5 now appear on the SPA
route, static assets, and the API proxy path.

### H1. CORS fully open with credentials allowed (`nginx.conf:93-97`)
`Access-Control-Allow-Origin $http_origin always;` reflects **any** requesting
origin verbatim, combined with `Access-Control-Allow-Credentials true always;`, on
the `/api/`, `/auth/`, `/system/` location block.

**CORRECTION 2026-07-05**: the original writeup here claimed this meant "any
external site can make authenticated cross-origin requests against the API,"
reasoning from `src/services/client.ts:20`'s `withCredentials: true`. That
overstated it — confirmed by reading the actual Go backend
(`/Users/abeshkov/proj/keyorix`) that **there is no cookie-based session at
all** (see the correction on the auth/session findings above); auth is a
Bearer token read from `localStorage`, which a cross-origin page has no access
to (same-origin-sandboxed) and can't attach to a request it sends. So under
today's actual auth model, this CORS hole did not by itself let an external
site replay a real user's session — `withCredentials` had nothing ambient to
send. It was still worth fixing (open CORS reflection is bad practice
regardless, and would have become a **real** authenticated cross-origin
exposure the moment any cookie-based credential existed — which Phase 1's
auth-cookie migration is about to introduce) — so removing it now, before
cookies exist, was the right sequencing, just for a slightly different reason
than originally stated.

**Reproduced live**: spun up the exact `nginx.conf` in a throwaway container, sent
`OPTIONS`/`GET` with `Origin: https://evil.example.com` (and two other arbitrary
origins) — all reflected verbatim with `Allow-Credentials: true`, including on a
502 (proving the `always` modifier applies regardless of upstream status).
Confirmed this is the exact file baked into the published Docker image
(`Dockerfile:15`, `.github/workflows/docker-publish.yml`) — not a dev-only config.

**Fix**: replace `$http_origin` passthrough with an nginx `map` allowlist of known
frontend origins (empty/no header for unmatched origins) before allowing
credentials.

### H2. CSP/Referrer-Policy (and more) silently dropped from every real response (`nginx.conf:52-112`)
The `http` block defines CSP, Referrer-Policy, X-Frame-Options,
X-Content-Type-Options, X-XSS-Protection via `add_header`. nginx's `add_header`
inheritance rule: a child `location` that defines **any** `add_header` of its own
stops inheriting **all** parent `add_header`s — it doesn't merge. Every
traffic-serving location in this file (static assets, the API/auth/system proxy,
even the SPA fallback `location /`) defines its own `add_header`s for unrelated
purposes (caching, CORS), so the carefully-written CSP never reaches a real
client.

**Reproduced live**: `GET /` → only 3 of 5 headers present (the SPA location
re-declares those 3, but not CSP/Referrer-Policy); `GET /app.js` (static asset
location) → **all 5 headers absent**; `GET /api/foo` → **all 5 headers absent**.
The elaborate CSP comment block in the config is effectively dead configuration.

**Fix**: nginx has no header-merge option — the 5 `add_header` directives must be
repeated in every location block that currently overrides `add_header`, or moved
into a shared `include` snippet referenced by each location.

---

## Confirmed MEDIUM-HIGH — trust-boundary gap, real but backend-dependent

**Status: client-side fix landed 2026-07-04** (`src/features/auth/api.ts`) —
`checkAuth()` is now called unconditionally after rehydration on every mount,
regardless of the persisted `isAuthenticated` flag. Verified: `type-check`,
`lint`, and the full `pnpm test --run` suite (320 tests, including
`ProtectedRoute`/`AdminRoute`/`PublicRoute`/`RequirePasswordChange` and the
auth-integration suite) all pass unchanged. The backend-enforcement half of
this finding (does the server independently re-authorize every request against
current DB state, not just trust token claims) still needs a cross-check with
whoever owns the Go backend — this repo can't verify that side.

### M1. `checkAuth()` skipped on mount whenever a session is already persisted (`src/features/auth/api.ts:23-36`)
```ts
await useAuthStore.persist.rehydrate();
const state = useAuthStore.getState();
if (!state.isAuthenticated) {
    await checkAuth();
}
```
Zustand's `persist` hydrates synchronously from `localStorage` (confirmed by
reading `node_modules/zustand/middleware.js`), so `isAuthenticated` is already
`true` for any previously-logged-in session by the time this check runs —
meaning `checkAuth()` (the only mount-time call that revalidates against
`GET /auth/profile`) never fires on reload of an existing session. Route guards
(`ProtectedRoute`/`AdminRoute`) render purely from this stale, client-editable
`user` object with no independent server check. No other hook in the app
incidentally revalidates the profile on mount (confirmed by search).

**Real-world severity depends on backend enforcement** (out of scope to verify
from this repo): if the backend independently re-authorizes every sensitive
action against current DB state, the impact is UI staleness (a revoked/demoted
user still *sees* admin screens/nav until their next API call 403s). If the
backend trusts JWT claims without a live per-request check, the impact escalates
to genuine privilege persistence for the life of the token.

**Fix**: call `checkAuth()` unconditionally after rehydration (or whenever a
token exists), not only when `isAuthenticated` is false.

---

## Other findings (MEDIUM and below), by vein

### Auth & session (`src/store/authStore.ts`, `src/utils/auth.ts`, `src/services/{auth,client}.ts`)
- **MEDIUM — FIXED 2026-07-04.** Real admin's own token sat in `localStorage`
  in plaintext (`adminToken`) simultaneously with the impersonation token while
  impersonating — doubled XSS blast radius during impersonation sessions.
  Deliberate product trade-off, made explicitly (not a mechanical fix): moved
  `adminToken`/`adminUser` to in-memory-only state, excluded from Zustand's
  `partialize`, so neither is ever written to `localStorage`. Cost: a page
  reload mid-impersonation now loses the one-click "return to admin" —
  `endImpersonation()` falls back to a full logout with an explicit error
  message ("Your admin session wasn't available in this tab... please sign in
  again") instead of the previous silent-and-broken restore attempt. `isImpersonating`
  itself is still persisted so the impersonation banner survives a reload.
  Covered by 2 new tests in `impersonation.test.ts` (partialize excludes both
  fields; the degraded-logout path fires the explanation). One known caveat:
  `LoginPage.tsx` clears the store's transient `error` field on its own mount
  effect (pre-existing behavior, unrelated to this change), so the explanation
  may not reliably survive the redirect-to-login in all cases — not fixed here
  since it's a narrow, low-frequency, self-recoverable (just log back in) edge
  case, and fixing the underlying clear-on-mount timing is a separate, broader
  LoginPage concern outside this change's scope.
- **MEDIUM — FIXED 2026-07-04.** No `storage`/`BroadcastChannel` cross-tab sync:
  logout/refresh in one tab didn't propagate; a stale tab kept using a
  revoked/rotated token until it independently 401s or was reloaded. Fix:
  `authStore.ts` now listens for the native `storage` event and calls
  `useAuthStore.persist.rehydrate()` whenever another tab writes (or clears)
  the shared `auth-storage` key — since the browser only fires that event in
  *other* tabs, this can't self-trigger. Covered by 4 new tests in
  `src/store/__tests__/multiTabSync.test.ts` (logout propagation, token-rotation
  pickup, unrelated-key no-op, `storage.clear()` signal).
- **LOW — FIXED 2026-07-04.** `rememberMe` was persisted client-side but never
  read back anywhere (confirmed dead by repo-wide search) — the checkbox's real
  effect is server-side (`services/auth.ts` sends it in the login body, and the
  backend presumably sizes `absolute_expires_at` accordingly), so this was
  purely redundant/confusing local bookkeeping with zero behavioral effect.
  Fix: removed the dead write path (`persistAuthData`'s `rememberMe` param,
  `REMEMBER_ME_KEY` storage key) — the checkbox itself and its real
  (server-side) effect are untouched.
- **LOW** — Client-side `absoluteExpiresAt` ceiling is forgeable via XSS, but only
  disables a client-side "skip refresh" shortcut/warning banner — server still
  enforces the real ceiling on refresh. *(Not actioned — informational; nothing
  to fix beyond what the server already enforces.)*
- **LOW — FIXED 2026-07-05.** End-impersonation server call was best-effort
  (`try/catch` swallowed failure); local state exited impersonation even if the
  backend revoke failed, leaving a live, un-revoked impersonation session
  server-side with no client-visible sign anything was wrong. Fix:
  `endImpersonation()` now only restores local state once the server call
  actually succeeds; on failure it leaves impersonation state untouched and
  rejects, so `ImpersonationBanner.tsx` can show a retry affordance instead of
  a false "you're back to normal" UI. Covered by a new test in
  `impersonation.test.ts` (rejects and leaves state unchanged on server
  failure).
- **LOW — reviewed, deliberately left for Phase 1/6.** Two independent,
  un-shared "read the current token" implementations (`services/client.ts`
  reads Zustand state; `services/auth.ts` hand-parses the same localStorage
  key — the latter exists specifically to avoid a circular import, since
  `authStore.ts` already imports `authService` from `services/auth.ts`).
  Considered fixing now (extracting one shared parse helper) but decided
  against it: the Phase 1 auth-cookie contract
  (`docs/PHASE1-AUTH-COOKIE-CONTRACT.md`) would delete this entire code path —
  there'd be no client-readable token left to parse at all — so a narrow fix
  now is likely throwaway work ahead of that decision. Confirmed still genuinely
  low-stakes: LOW severity, "not a live race today," latent-only.
- **LOW** — `authApi`'s axios instance has no expiry-awareness or its own 401
  auto-refresh (unlike `apiClient`) — currently harmless since `checkAuth()`
  handles the resulting 401, but duplicated/divergent logic. *(Same Phase 1/6
  deferral as above.)*
- **LOW — FIXED 2026-07-04.** Two unsynchronized inactivity-timeout
  implementations (`useAuth()`'s real timer vs. `SessionTimeoutWarning.tsx`'s
  own independent 5-minute timer/listeners) could disagree about when to warn
  vs. actually log out. Fix: `useAuth()` is now the single source of truth —
  it tracks one deadline and exposes `sessionTimeLeftMs` (non-null only once
  inside the warning window, switching from a single scheduled timeout to
  per-second ticks only during that window to avoid a whole-session 1s
  re-render cost); `SessionTimeoutWarning.tsx` is now purely presentational,
  with no timer or DOM listeners of its own.
- **CORRECTION 2026-07-05**: the line below originally read "refresh token
  itself is HttpOnly-cookie-only, never localStorage-readable" — that was
  **wrong**, inferred from a frontend code comment
  (`withCredentials: true, // Important for HTTP-only cookies` in
  `services/client.ts`/`services/auth.ts`) rather than verified against the
  actual backend. Confirmed by reading the Go repo directly
  (`/Users/abeshkov/proj/keyorix`, `server/http/handlers/auth.go`): **there are
  no cookies at all today.** There is no separate refresh token — login issues
  a single session token returned in the JSON body, and `POST /auth/refresh`
  rotates that *same* token (reads it via `Authorization: Bearer`, deletes the
  old session row, creates a new one) rather than exchanging a distinct
  refresh credential. So the one thing this repo's audit called "checked and
  clean" was actually never true — the session token has been JS-readable/
  localStorage-stored *and* self-rotating via a JS-readable value the whole
  time, with no HttpOnly anything anywhere in the stack. This is exactly why
  Phase 1's auth-storage decision is a real one, not confirmatory box-checking
  — see `docs/PHASE1-AUTH-COOKIE-CONTRACT.md`, now updated to reflect the
  actual (cookie-free) backend starting point.
- **Checked and clean**: hydration is synchronous (no fail-open render flash);
  `RequirePasswordChange` is UX-only with backend enforcement documented;
  single-flight refresh dedup has no race across the two axios instances;
  inactivity timer only resets on genuine user-interaction DOM events and calls
  a real server logout.

### XSS / content-injection
- **No `dangerouslySetInnerHTML` anywhere in the repo; no markdown renderer.**
  Every user-controlled string sink checked (toasts, Alert, CmdKSearch, table
  cells, modal titles, audit log free text, share/invite dialogs) relies on
  JSX's default escaping with no bypass found — the Go backend's proven
  CSV/Slack/Teams unescaped-name bug class does not carry over to this
  frontend renderer (CSV export is backend-generated blob download, not
  client-assembled).
- **MEDIUM — FIXED 2026-07-04.** Copy-to-clipboard for secret values / MFA
  recovery codes / API tokens / admin setup-links / OTPs never auto-cleared
  (the existing `copyToClipboard()` util that does clear-after-timeout was dead
  code, unused by any real call site). Fix: routed all 9 real call sites
  (`useSecretReveal.ts`, `SecretDetailView.tsx`, `MfaSection.tsx`,
  `StaleAccountsSection.tsx`, `AdminPage.tsx` ×2, `ServiceAccountsPage.tsx`,
  `ProfilePage.tsx`, `UserDetailPage.tsx`, `KeyorixConnectPage.tsx`) through
  `copyToClipboard()`, and wired its default timeout to the previously-dead
  `VITE_CLIPBOARD_CLEAR_TIMEOUT` config instead of a hardcoded value. Verified:
  `type-check`, `lint`, full test suite (320 tests) all pass.
- **MEDIUM — FIXED 2026-07-04.** Revealed secret plaintext lingered in the React
  Query cache up to 10 minutes (`gcTime`) after the detail view was
  hidden/closed, reachable by any same-origin script referencing the
  module-level `queryClient`. Fix: `SecretDetailView.tsx` now explicitly
  `removeQueries`s the versions query both when the value is hidden and on
  unmount, rather than relying on the cache-eviction timeout.
- **LOW — FIXED 2026-07-04.** Audit log page echoed an unrecognized `?filter=`
  URL param verbatim in fallback UI text (escaped by JSX, not exploitable, but
  a reflection smell). Fix: falls back to a fixed "Custom filter" label instead.
- **LOW — FIXED 2026-07-04.** `SSOCompletePage.tsx` passed a raw `return_to`
  fragment param straight to `navigate()` with no same-origin allowlist; not
  currently exploitable as an open redirect (browser blocks cross-origin
  `pushState`), but had no defense-in-depth validation. Fix: added
  `isSafeReturnTo()`, requiring a single leading `/` (rejecting `//`/`/\`
  protocol-relative forms) before trusting the param, falling back to `/`.

### Build, deploy, supply chain
- **MEDIUM — FIXED 2026-07-04.** Production build shipped JS source maps
  (`vite.config.ts:35` unconditional `sourcemap: true`), copied wholesale into
  the image, not excluded by any nginx rule — publicly downloadable, exposing
  de-minified source structure. Fix: `sourcemap: mode !== 'production'`; ran
  `pnpm build` and confirmed zero `.map` files in `dist/`.
- **MEDIUM — FIXED 2026-07-04.** No HSTS header anywhere in `nginx.conf`. Fix:
  added `Strict-Transport-Security: max-age=63072000; includeSubDomains` to
  every location that sets its own header block; verified present on a live
  response in a throwaway container (safe on plain-HTTP self-host deployments —
  browsers only honor HSTS over an actual HTTPS connection).
- **MEDIUM — FIXED 2026-07-04.** `docker-compose.yml:34,46` committed a
  hardcoded default `DB_PASSWORD`/`POSTGRES_PASSWORD=secret` for the self-host
  reference compose. Fix: replaced with required `${DB_PASSWORD:?...}`-style
  interpolation (no default), documented in `.env.example`; confirmed
  `docker compose config` fails fast with a clear message when unset and
  resolves correctly when set.
- **LOW** — `.env.example` defaults `VITE_ENABLE_DEBUG=true`; risk if
  copy-pasted straight into `.env.production` (the flag only gates a
  console.error of failed-request status/message, never request/response
  bodies, so low blast radius even if shipped).
- **LOW / hygiene** — `pnpm audit`: 4 high (`form-data` via axios, 3x/various
  via `undici`) — confirmed **not shipped** to the production bundle (axios's
  `browser` field remaps away the vulnerable Node code path; `undici` only
  reaches the graph via `jsdom`/`vitest` devDependencies). Worth bumping for
  hygiene, not exploitable in the shipped product.
- **Checked and clean**: Dockerfile is a correct multi-stage build, no
  secrets/`.env` baked into any layer (`.dockerignore` excludes them); axios
  pinned at `1.16.1`, well past all known axios CVEs; no typosquats in
  `package.json`; no third-party `<script src>` in `index.html` (no SRI concern
  because nothing external is loaded).

### Client-side authorization theater
- **MEDIUM, needs backend cross-check** — `ProjectMembersTab.tsx`'s add-member /
  role-change / remove-member controls have **zero** client-side role gating
  (unlike the sibling `MachineIdentitiesSection` in the same tab, which does
  check `isAdmin`) — the entire trust boundary is server-side with no client
  hint at all; needs confirmation that `POST/PUT/DELETE
  /api/v1/projects/:id/members*` independently verify project-admin-equivalent
  role server-side.
- **MEDIUM, needs backend cross-check** — `RolesPoliciesPage.tsx`'s "delete
  role" button disables only via a client-side name match against
  `BUILT_IN_ROLES`; needs confirmation `DELETE /api/v1/roles/:id` independently
  rejects built-in role deletion server-side (a raw API call bypasses the UI
  disable instantly if not).
- **MEDIUM, needs backend cross-check** — Personal Access Token creation lets a
  user type arbitrary `extraPermissions` free text, sent verbatim as requested
  `scopes`; client only dedupes/trims, never validates it's a subset of the
  caller's actual permissions — needs confirmation the token-creation endpoint
  intersects requested scopes against the caller's live permission set
  server-side.
- **MEDIUM, needs backend cross-check** — `authStore.ts`'s periodic token
  refresh updates only the token/expiry, never `user.roles`/`user.permissions`
  — a demoted/promoted user's admin nav and permission-gated buttons stay stale
  for the rest of their session (same root cause as M1 above); needs
  confirmation the backend re-validates role/permission per-request rather than
  trusting cached token claims.
- **LOW, needs backend cross-check** — `UserDetailPage.tsx` hides
  suspend/reactivate/force-logout on "self" purely client-side; low severity
  (self-lockout, not privilege escalation) but worth confirming server-side.
- **LOW/MEDIUM, fix now (client-side design bug, independent of backend)** —
  `MachineIdentitiesSection.tsx`/`DynamicSecretsPage.tsx`/`LeasesPanel.tsx` gate
  UI on the global `isAdmin` flag, but their own code comments describe the real
  requirement as a **project/config-scoped** permission — a mismatch between
  documented model and implemented gate (false-negative/false-positive UX, not
  a security hole since the backend presumably enforces the real scoped check,
  but worth fixing regardless of backend behavior).
- **Checked and clean**: no case found where the client is the *sole*
  enforcement point for a mutating action — every mutation site handles
  real HTTP error responses (401/403) via a central axios interceptor plus
  per-call `onError`; several components (`TransferOwnership.tsx`,
  `LeasesPanel.tsx`, `ProjectMembersTab.tsx`'s invite/request sections) are
  explicitly documented as UX-only with backend enforcement, and one pattern
  (query-403-renders-nothing in `ProjectMembersTab.tsx`) is the most robust
  approach found — it asks the backend every time rather than trusting a
  cached flag. Also found: `ProtectedRoute`/`AdminRoute`'s `requiredPermissions`
  prop is plumbed through but never actually passed a value anywhere in
  `App.tsx` — dead capability, not a vulnerability.

---

## Recommended next steps

1. ~~H1 and H2 (nginx CORS + header inheritance) are live in the currently
   published production image~~ — **done 2026-07-04**, along with the three
   build/deploy MEDIUMs (source maps, HSTS, compose default password).
2. ~~M1 (checkAuth skip)~~ — **client-side fix done 2026-07-04.** The backend
   half (does the server independently re-authorize every request, not trust
   token claims), plus the four "needs backend cross-check" authz-theater
   items (`ProjectMembersTab` member mutations, `RolesPoliciesPage` built-in-role
   delete, PAT scope intersection, `UserDetailPage` self-action guards) — none
   of these are checkable from this repo alone. Turned into a concrete
   checklist with exact endpoints for the Go-repo side:
   `docs/RBAC-BACKEND-CROSSCHECK.md`.
3. ~~The two secrets-handling MEDIUMs (clipboard auto-clear, query-cache
   retention) and the two audit/SSO LOWs~~ — **done 2026-07-04.**
4. ~~No multi-tab session sync~~ and ~~two unsynchronized inactivity-timer
   implementations~~ and ~~dead `rememberMe` flag~~ — **done 2026-07-04.**
5. **Still open, deliberately not touched — each needs a decision this repo
   can't make unilaterally, not a mechanical fix:**
   - Scoped-vs-global permission mismatch (`MachineIdentitiesSection.tsx`,
     `DynamicSecretsPage.tsx`, `LeasesPanel.tsx` gate on the global `isAdmin`
     flag though their own comments describe a project/config-scoped
     requirement) — **not a quick fix**: there is no project-scoped
     permission data on the client today (`User.permissions` is a flat global
     `string[]`, confirmed via `src/types/index.ts`) and no existing
     "my permissions in this project" endpoint to call. Fixing this properly
     needs a real client-server contract decision, not a client-only patch —
     flag for Phase 1 alongside the other architecture decisions.
   - ~~Real admin token double-exposure during impersonation~~ — **decided and
     fixed 2026-07-04**: moved to in-memory-only (see above).
   - ~~Best-effort end-impersonation revoke~~ — **fixed 2026-07-05.**
   - Remaining LOWs, deliberately not actioned: forgeable (client-UX-only)
     `absoluteExpiresAt` (informational only); dual token-read implementations
     and `authApi`'s lack of its own 401 auto-refresh — both reviewed and
     confirmed as Phase 1/6's job (the auth-cookie contract would delete this
     code path outright, so a narrow fix now is likely throwaway work).
6. Feed this file's findings into Phase 1 (the auth-storage decision) and the
   Phase 3-6 migration order as the plan intends.
