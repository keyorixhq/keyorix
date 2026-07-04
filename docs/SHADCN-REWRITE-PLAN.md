# keyorix-web: pre-rewrite audit + shadcn/ui migration plan

**Status: IN PROGRESS (Phase 0) as of 2026-07-03.** The parallel backend (keyorix
Go repo) security hardening campaign (round 69+) has exhausted new veins and moved
to empirical reproduction of existing findings rather than turning up new ones, so
the founder decided the attention-splitting risk that justified the original queue
is low enough to start Phase 0 now, concurrently with the tail of that campaign.
See the Go repo's `docs/security/HARDENING-BACKLOG.md` / `BUGS.md` for that
campaign's current state.

Context: this repo (`keyorix-web`, ~29,600 LOC React 19 + TS + Vite SPA) has never
been touched by any of the 69+ rounds of the Go-backend hardening campaign — it was
explicitly marked "not in this tree / out of scope" there. This plan starts from
zero. BACKLOG.md's existing "shadcn/ui rewrite (umbrella)" item is the origin of
this plan; treat this file as its detailed breakdown.

## Guiding principle

The current stack (React 19, Vite, TanStack Query, Zustand, Tailwind v4, RHF/Zod as
installed deps, Vitest/Playwright) is already lean and modern — no framework
duplication at the data/state/routing/styling layer. Don't rewrite those. Scope the
rewrite to the component layer (shadcn/ui) and the specific duplicated/dead wiring
found below. Audit findings inside components being torn out anyway (Button, Input,
Select, Alert) are low priority to fix pre-rewrite; findings in surfaces that
survive the rewrite unchanged (auth flow, API client, storage, build/deploy config)
are high priority to fix or decide now.

---

## Technology stack

**Keeping as-is** (already modern, no framework-level duplication found):
- React 19 + Vite + TypeScript
- React Router v7 — routing
- TanStack Query v5 — server state/caching
- Zustand v5 — client/UI state (auth store, UI store, project MRU)
- Tailwind CSS v4 — styling
- axios — HTTP client (consolidating from two instances down to one, Phase 6)
- Vitest + Testing Library — unit tests
- Playwright — e2e (rebuilt in Phase 8, not replaced)
- pnpm, ESLint, Prettier — tooling

**Adding:**
- **shadcn/ui** (Radix UI primitives + Tailwind) — replacing the 11 hand-rolled UI
  components (`Button`, `Input`, `Select`, `Alert`, `Modal`, `Dropdown`, `Toast`,
  `Dialog`, `CmdKSearch`) in Phases 3-4.
- **react-hook-form + zod** — already installed but currently unused (every form
  hand-rolls `useState` validation instead); Phase 5 actually puts them to use,
  paired with shadcn's `Form` component.
- **MSW** (Mock Service Worker) — new addition for the e2e rebuild (Phase 8), since
  the current suite has no API mocking at all.

**Still an open decision** (Phase 1, depends on Phase 0's audit findings):
- Auth token storage: httpOnly/Secure/SameSite cookie vs. hardened localStorage.

**Nothing else changes** — no new state manager, no new router, no new build tool,
no new server-state library. The rewrite is scoped to the component layer + the
specific dead/duplicated wiring, not a stack swap.

---

## Phase 0 — Pre-rewrite audit (bug hunt keyorix-web from scratch)

Run this the same way the Go campaign runs: parallel agents per vein below,
adversarially re-verify anything rated HIGH before trusting it, tag every finding
**"fix now" vs. "moot after rewrite."**

### Auth & session (highest priority — survives the rewrite)
1. Token storage/lifecycle (`src/store/authStore.ts`, `src/utils/auth.ts`,
   `src/services/auth.ts`) — what's recoverable from `localStorage` by a same-origin
   script (access token, refresh token, `rememberMe`, absolute-expiry ceiling), what
   an XSS payload could exfiltrate or forge.
2. Impersonation state (`adminToken`/`adminUser`/`isImpersonating` in
   `authStore.ts`) — can localStorage be hand-edited to fake `isImpersonating` /
   inject an `adminToken` the backend will still honor if replayed? Does exiting
   impersonation clear both tokens?
3. Route guards (`ProtectedRoute`/`PublicRoute`/`AdminRoute`,
   `RequirePasswordChange` in `src/components/layout/`) — fail-open flash of
   protected content before `checkAuth()`/`persist.rehydrate()` resolves on first
   paint? Are role/permission checks re-derived from the token or trusted from
   stale client state?
4. Single-flight refresh dedup (`inFlightRefresh` in `authStore.ts`) plus the dual
   axios-instance token read (`apiClient` reads from Zustand, `authApi`
   hand-parses the same localStorage key, `services/client.ts` vs
   `services/auth.ts`) — race where one client refreshes and the other still
   sends the stale token?
5. Multi-tab session sync — does logout/refresh in one tab propagate to others
   (`storage` event), or can a stale tab keep using a revoked token?
6. Session-inactivity timeout — can it be reset by a background timer/no-op
   request; does it call the server-side revoke, not just redirect client-side?

### XSS / content-injection surfaces
7. Grep for `dangerouslySetInnerHTML` and every place a secret *name*, project
   name, user display name, or share/invite message is rendered (toasts, `Alert`,
   `CmdKSearch`, dashboard widgets) — the Go backend campaign already found
   unescaped names reaching Slack/Teams/CSV/CLI-JSON output (#328, #384 and
   siblings), so this bug class is proven in this product; never checked on this
   renderer specifically.
8. Copy-to-clipboard / "reveal secret value" UI — confirm values aren't logged to
   `console` (the `ENABLE_DEBUG`-gated axios logger must never log request/response
   bodies), aren't left in the DOM after modal close.
9. URL/query-param reflection — any secret ref, project ID, or filter value read
   from the URL and rendered without treating it as untrusted.

### Build, deploy, and supply chain
10. `nginx.conf` — CSP, `X-Frame-Options`/`frame-ancestors`, HSTS; confirm no
    dev-only convenience (source maps, `ENABLE_DEBUG`) ships to the prod image.
11. `Dockerfile` — no secrets/`.env` baked into a layer; multi-stage build drops
    dev dependencies.
12. `VITE_*` env vars — anything prefixed `VITE_` is inlined into the client bundle
    at build time; confirm nothing sensitive (API keys, internal URLs) leaks this
    way.
13. `pnpm audit` / lockfile — dependency CVEs (check the pinned axios version
    against known SSRF/redirect CVEs); sanity-check `pnpm-workspace.yaml` has no
    typosquat-adjacent references.
14. `index.html` — no external third-party `<script src>` (supply-chain/SRI
    concern) unless explicitly intended.

### Client-side authorization theater
15. Anywhere the UI hides a button/menu item based on role/permission — confirm
    it's UX-only and the actual mutating call is still backend-enforced; the
    frontend must never uniquely trust a client-computed permission for anything
    that skips a server round-trip.

Phase 0 output feeds directly into which files get special care in Phases 3-6.

### Baseline metrics (measured 2026-07-03) — use to prioritize Phase 0 and the migration order

Coverage: `go test -coverprofile` (backend, merged/statement-weighted) and
`pnpm test:coverage` (frontend, vitest). Complexity: McCabe cyclomatic complexity,
computed via a stdlib-only `go/ast` script for the backend (`gocyclo` install was
sandbox-blocked) and ESLint's built-in `complexity` rule for the frontend — the two
aren't perfectly apples-to-apples (ESLint also scores inline arrow functions; the Go
script only scores top-level func decls) but both use the same McCabe formula, so
the shape/thresholds are comparable.

**Coverage**

| | Statements | Branches | Functions | Lines |
|---|---|---|---|---|
| Go backend (main module; `operator/` is a separate module, not included) | 38.4% | — | — | — |
| keyorix-web | 54.0% | 48.8% | 37.1% | 55.7% |

Backend coverage is very uneven by package: `internal/core` 73.2%, `server/http`
87.6%, `internal/crypto` 87.7% are well covered, but **`server/http/handlers` — where
most of the Go campaign's HIGH findings live — is only 19.2%**, and most
`internal/cli/*` packages (34 subcommand dirs) sit at 0-25% (several genuinely
untested: `anomalies`, `auth`, `breakglass`, `connect`, `group`, `legalhold`,
`license`, `offline`, `risk`, `run`, `sod`, `status`). On the frontend, the
service-layer files handling auth-adjacent API calls are the weak spot:
`services/auth.ts` 6.1%, `services/admin.ts` 3.0%, `services/serviceAccounts.ts`
3.4%, `services/rbac.ts` 17.6% — exactly the auth/session vein Phase 0 item #1-6
already flags as highest priority.

**Cyclomatic complexity**

| | Functions analyzed | Avg | >10 (moderate) | >20 (high) | >50 (very high) |
|---|---|---|---|---|---|
| Go backend | 3,153 | 4.01 | 168 (5.3%) | 18 (0.6%) | 3 (0.1%) |
| keyorix-web | 870 | 5.41 | 81 (9.3%) | 25 (2.9%) | 5 (0.6%) |

Both averages are healthy (1-10 is "simple, low risk" under McCabe), but the
frontend has ~2x the backend's hot-spot rate. **Frontend outliers are page-level
components — exactly the "God component" shape the rewrite should break up as it
migrates them**, so treat this as the migration-order tiebreaker within Phases 3-5:

- `pages/dashboard/DashboardPage.tsx:183` — complexity 90
- `pages/secrets/SecretsListPage.tsx:45` — 65
- `pages/admin/AdminPage.tsx:82` — 63
- `pages/projects/ProjectSettingsTab.tsx:18` — 60
- `features/secrets/SecretDetailView.tsx:87` — 56

**Actionable conclusion**: low-coverage + high-complexity in the same file is the
highest-value target list for both Phase 0 and the migration order. On the frontend
that's the five page components above (audit them first in Phase 0's XSS/rendering
vein, migrate them first in Phases 3-5 since they're getting the most rewrite value
per file). On the backend (out of scope for this plan, but worth flagging back to
the hardening campaign) it's `server/http/handlers` as a package — 19.2% coverage
directly under the code that produces most of that campaign's HIGH findings.

---

## Phase 1 — Architecture decisions (before touching any component)

Decide once; retrofitting after the rewrite is double the work:
- **Auth storage**: ~~httpOnly/Secure/SameSite cookie vs. hardened
  localStorage~~ — **decided and implemented 2026-07-05**: httpOnly cookie,
  coordinated with the backend (same person owns both repos). See
  `docs/PHASE1-AUTH-COOKIE-CONTRACT.md` for the full spec/status and the plan
  file `/Users/abeshkov/.claude/plans/iterative-cooking-sifakis.md` for the
  approved implementation plan. Phase C (removing the now-vestigial
  Bearer-fallback and JSON-body token) is intentionally deferred pending an
  operational bake-in period — see that doc.
- **Forms**: standardize on RHF + Zod + the currently-unused `Form.tsx` pattern for
  every form going forward; retire the raw-`useState` validation pattern used by
  every current form (`LoginForm`, `PasswordResetForm`, `SetupForm`, etc.).
- **API client**: collapse `apiClient`/`authApi` into one instance with one
  token-read path. Partially addressed as a side effect of the auth-cookie
  migration — `services/auth.ts`'s hand-parse-localStorage interceptor (the
  original reason for two instances existing) is gone, since there's no
  client-held token to parse anymore. The two axios instances themselves are
  still separate (still avoids the same circular-import constraint) — full
  collapse into one instance remains open if still wanted.
- **Code-splitting**: route-level `React.lazy`/`Suspense`, decided once so every
  migrated page follows the same convention.

## Phase 2 — shadcn setup & component inventory

- Install shadcn CLI; map existing CSS variables (`--bg-app`, `--accent`, etc. in
  `src/index.css`) onto shadcn's theming layer so dark/light theming isn't lost.
- Freeze the current component inventory (11 custom UI components in
  `src/components/ui`, 84 feature files, 14 page dirs) as the migration checklist.

## Phase 3 — Migrate leaf primitives

`Button`, `Input`, `Select`, `Alert` → shadcn equivalents. Lowest blast radius,
highest reuse — validates the theming bridge first.

## Phase 4 — Migrate compound components

`Modal`, `Dropdown`, `Toast`, `Dialog`, `CmdKSearch` → shadcn/Radix equivalents
(Dialog, DropdownMenu, Toast/Sonner, Command). Apply any Phase 0 findings specific
to these components as they're rebuilt.

## Phase 5 — Migrate forms, feature by feature

Rebuild each hand-rolled form on RHF + Zod + shadcn `Form`, applying any Phase 0
auth/validation findings for that flow as it's touched.

## Phase 6 — Auth & API consolidation

Implement the Phase 1 auth-storage decision and the single-axios-client
consolidation. Do this once the login/auth-adjacent pages are already being
rebuilt in Phase 5, so it's one touch-pass, not two.

## Phase 7 — Robustness pass

Wire `ErrorBoundary` (`src/components/ui/ErrorBoundary.tsx`) at root + per-route;
add route-level `Suspense`/lazy imports across all migrated pages.

## Phase 8 — Test suite rebuild

Add stable `data-testid`s to new components as they land (Phases 3-6); add
MSW/`page.route` mocking; rewrite `e2e/auth.spec.ts` and `e2e/secrets.spec.ts`
against the new components; wire `test:e2e` into CI.

## Phase 9 — Formatting & cleanup

Adopt enforced Prettier (`.prettierrc` matching house style: 4-space, single
quotes) once the rewrite settles, so the one-time ~131-file reformat doesn't
collide with in-flight rewrite branches.

## Phase 10 — Adversarial re-audit

Re-run the highest-value Phase 0 veins (XSS-in-rendering, token handling, route
guards) against the *rewritten* code — confirm the rewrite didn't quietly
reintroduce `dangerouslySetInnerHTML`-shaped bugs or regress the Phase 1
auth-storage decision.
