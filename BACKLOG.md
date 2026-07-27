# Engineering Backlog

Deferred technical work and the decisions behind it. Product/feature roadmap
lives in the app itself (`src/pages/roadmap/RoadmapPage.tsx`); this file tracks
internal engineering work only.

_Last updated: 2026-07-27._

## The shadcn/ui rewrite (umbrella) — COMPLETE

The full phased migration is done (Phases 0–10, PRs #107–#116 on main,
2026-07-27). See `docs/SHADCN-REWRITE-PLAN.md` for the plan and decisions.

Remaining follow-ons (no longer blocked):

- **Restore `App` test coverage.** `App.tsx` is now stable post-rewrite;
  `App.test.tsx` was a tombstone stub and was removed. Re-add against the new
  structure.
- **Accessibility test coverage.** The old `accessibility.test.ts` referenced
  deleted components. Write fresh a11y tests; re-add `jest-axe` at that point.

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

- Removed as dead (declared but imported nowhere): **`date-fns`**, **`jest-axe`**.
  Re-add at latest only when actually used (jest-axe with the a11y tests above).
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
