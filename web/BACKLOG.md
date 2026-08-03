# Engineering Backlog

Deferred technical work and the decisions behind it. Product/feature roadmap
lives in the app itself (`src/pages/roadmap/RoadmapPage.tsx`); this file tracks
internal engineering work only.

_Last updated: 2026-08-01._

## Q3 2026 roadmap features — COMPLETE

All frontend items from the Q3 roadmap shipped across PRs #121–#124:

- **RBAC audit log tab** (PR #121) — new "RBAC Events" tab on `/audit`, actor /
  date filters, pagination, CSV export. Existing `useAuditLog` hook extended with
  `actor`, `dateFrom`, `dateTo` params.
- **Per-framework compliance reports** (PR #122) — framework tab bar (All / ISO
  27001 / SOC 2 / NIS2 / DORA / ENS) above the control matrix, per-framework
  compliance score with colour-coded progress bar.
- **Effective permissions in Members tab** (PR #123) — static capability matrix
  per project role, expandable member rows, collapsible role legend.
- **OIDC Workload Identity Federation UI** (PR #124) — "OIDC Federation" tab on
  `/admin/service-accounts`; trust-config CRUD, issuer presets (GitHub Actions,
  GitLab, GCP, Azure), bound-SA picker, GitHub Actions usage guide. Graceful
  404/501 banner while backend is pending (deferred to Q4).

Project-scoped role assignments and project switcher were already implemented
before the campaign started (confirmed by codebase survey).

## The shadcn/ui rewrite (umbrella) — COMPLETE

The full phased migration is done (Phases 0–10, PRs #107–#116 on main,
2026-07-27). See `docs/SHADCN-REWRITE-PLAN.md` for the plan and decisions.

Follow-ons — also complete:

- **App route coverage** — 20 integration tests in `src/__tests__/App.test.tsx`
  (PR #117, 2026-07-27). Verifies every guard is wired to the right route.
- **Accessibility coverage** — 27 axe tests across Button, Input, Alert,
  LoginForm, PasswordResetForm, SetupForm (PR #118, 2026-07-27). `jest-axe`
  re-added and wired into the global Vitest setup.

## End-to-end tests (Playwright) — actually rebuilt 2026-07-31

This doc previously claimed the suite was "rebuilt 2026-07-27" with API
mocking, testids, and CI wiring — none of that had actually happened. The
specs still assumed a live backend (real login endpoint, seeded users),
referenced a `data-testid="email-input"` that never existed (`LoginForm` has
always used `username`, not email), asserted on UI text (`getByText('Dashboard')`)
that doesn't exist in the current app, and `ci.yml` had no `e2e` job at all.

Actually done now:

- `data-testid` added to `LoginForm`, `Header`'s user-menu trigger, and the
  secrets list/create-modal buttons in `SecretsListPage.tsx`.
- All 3 specs rewritten against `page.route` mocking — no backend needed. See
  `e2e/mocks.ts` for the shared mock helpers.
- `playwright.config.ts`: Chromium-only project, `pnpm dev` for the web server.
- `e2e` job added to `.github/workflows/ci.yml`, running after `gate` passes.

Along the way this surfaced two real, unrelated production bugs, both fixed
in the same effort (no e2e coverage had ever exercised these paths for real):

- `authStore.checkAuth()` had `if (get().isLoading) return;` as its first
  line — since `isLoading` starts `true` by design, this made the *only* call
  to `checkAuth()` (on every fresh page load) a silent no-op. The app got
  stuck on an infinite "Loading…" spinner on first load, every time. Fixed by
  using a dedicated `checkAuthInFlight` module flag instead of overloading
  `isLoading` for re-entrancy.
- `PublicRoute`/`ProtectedRoute` unmounted their children on *every*
  `isLoading` flip, not just the initial check — so a plain login attempt
  (which briefly sets `isLoading: true`) unmounted `LoginPage` mid-request.
  The remount's `clearError()` mount-effect then wiped the error message
  before it was ever visible, and the form fields reset. A failed login
  showed no feedback at all. Fixed by adding `hasCheckedAuth` to `AuthState`
  (true once the initial bootstrap resolves) and gating the route guards'
  full-page spinner on that instead of `isLoading`.

## Formatting / Prettier — enforced 2026-07-27, CI gate fixed 2026-07-30

Prettier is enforced. `.prettierrc` was added with house style (`tabWidth:
4`, `singleQuote: true`), all ~131 source files were reformatted in one
standalone commit (Phase 9, PR #115).

`pnpm format:check` was *not* actually wired into `ci.yml` at the time,
despite this doc's earlier claim — so nothing enforced it going forward. 54
files drifted over the following days. Fixed 2026-07-30: drifted files
reformatted in a standalone commit, `format:check` added as its own CI step.

## Dependency maintenance

- Removed as dead (declared but imported nowhere): **`date-fns`**. Re-add only
  when actually used.
- **`jest-axe`** was re-added in PR #118 for the a11y test suite; bumped to
  11.x 2026-08-01.
- `tsconfig` was modernized (`moduleResolution: bundler`, no `baseUrl`), ready
  for the eventual TS 7. **Deliberately staying on TypeScript 6.x for now**
  (2026-08-01): TS 7 is the new Go-native compiler with no stable
  programmatic API until 7.1 (still months out per Microsoft), and
  `typescript-eslint` — which `pnpm lint` depends on — closed TS7 support as
  "not planned" until that API ships. Revisit once it has real support.
- 2026-07-30/31: 26 minor/patch deps updated; `jsdom` 30, `@testing-library/jest-dom`
  7, and a pre-existing unmet `@testing-library/dom` peer (now pinned
  explicitly at `^10.4.1`) landed 2026-08-01. Run `pnpm outdated` for current
  state rather than trusting a "complete" snapshot here — it drifts.

## Refactor candidates (cyclomatic complexity) — regenerated 2026-08-01

See [`docs/REFACTOR-CANDIDATES.md`](docs/REFACTOR-CANDIDATES.md). The
2026-07-30 version was generated with `lizard`, which does naive
brace-counting and badly misjudges JSX-returning functions (JSX's `{expr}`
looks like a code block to a brace-counter, but isn't) — its two "worst
outliers" (`buildCreateModalContent` CCN 115, `renderExpiringSecretsSection`
CCN 103) turned out to have *real* complexity of 12 and 4. Regenerated with
ESLint's own `complexity` rule instead (same JSX-aware parser `pnpm lint`
already uses) — 43 functions above complexity 15, an almost entirely
different set led by large page-level components (`DashboardPage`,
`SecretsListPage`, `AdminPage`, ...) rather than the render-helper functions
the old list pointed at. A cluster of `normalize*()`/API-object-method
functions in `src/services/*.ts` also shows up despite being short —
field-mapping code, low risk. Not a dedicated-sweep item — fix
opportunistically when already touching one of these functions.

## Working agreement (how changes land here)

Conventions established over the recent maintenance arc:

- Keep the green gate between every change: `type-check`, `lint` (0 errors;
  warnings under the 40 cap), `build`, `test`.
- One focused commit per logical change; dependency bumps isolated so any
  fallout is easy to attribute.
- Surface surprising findings (e.g. a "format-only" bump that turns out to
  rewrite the whole repo) rather than pushing through them.
