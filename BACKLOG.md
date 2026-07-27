# Engineering Backlog

Deferred technical work and the decisions behind it. Product/feature roadmap
lives in the app itself (`src/pages/roadmap/RoadmapPage.tsx`); this file tracks
internal engineering work only.

_Last updated: 2026-07-27._

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

## End-to-end tests (Playwright) — rebuilt 2026-07-27

Specs were rewritten with `page.route` API mocking (no real backend required).
`data-testid` attributes added to LoginForm, Header. `playwright.config.ts`
switched to pnpm and Chromium-only. The `e2e` job is now wired into CI (runs
after the unit gate passes). See `.github/workflows/ci.yml`.

## Formatting / Prettier — enforced 2026-07-27

Prettier is now enforced. `.prettierrc` was added with house style (`tabWidth:
4`, `singleQuote: true`), all ~131 source files were reformatted in one
standalone commit (Phase 9, PR #115), and `pnpm format:check` runs in CI.

## Dependency maintenance

The upgrade campaign is **complete** — `pnpm outdated` is empty.

- Removed as dead (declared but imported nowhere): **`date-fns`**. Re-add only
  when actually used.
- **`jest-axe`** was re-added in PR #118 for the a11y test suite.
- TypeScript is on 6.x; `tsconfig` was modernized (`moduleResolution: bundler`,
  no `baseUrl`) so it is clean for the eventual TS 7.

## Working agreement (how changes land here)

Conventions established over the recent maintenance arc:

- Keep the green gate between every change: `type-check`, `lint` (0 errors;
  warnings under the 40 cap), `build`, `test`.
- One focused commit per logical change; dependency bumps isolated so any
  fallout is easy to attribute.
- Surface surprising findings (e.g. a "format-only" bump that turns out to
  rewrite the whole repo) rather than pushing through them.
