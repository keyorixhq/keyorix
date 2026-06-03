# Engineering Backlog

Deferred technical work and the decisions behind it. Product/feature roadmap
lives in the app itself (`src/pages/roadmap/RoadmapPage.tsx`); this file tracks
internal engineering work only.

_Last updated: 2026-06-03._

## The shadcn/ui rewrite (umbrella)

The planned migration of the UI to shadcn/ui is the single largest pending
item, and several smaller deferrals are blocked on it. Until it is scoped,
the dependents below stay parked. When it lands, revisit each.

**Unblocks / should be done as part of it:**

- **Restore `App` test coverage.** The old `App.test.tsx` was a tombstone stub
  (referenced a deleted i18n module + stale UI assertions) and was removed.
  `App.tsx` is almost entirely page composition that the rewrite will reshape,
  so coverage is best (re)written against the new structure.
- **Accessibility test coverage.** The old `accessibility.test.ts` referenced
  `LoginForm`/`SecretForm` deleted in the May 2026 refactor. Write fresh a11y
  tests against the rewritten components. Re-add `jest-axe` (at latest) at that
  point — see below.
- **Formatting policy.** Adopting enforced Prettier (see below) is best
  coordinated with the rewrite so the large reformat doesn't collide with it.

## End-to-end tests (Playwright) — stale, needs rewrite

The `e2e/` Playwright specs are **stale** (verified 2026-06-03, not just
unrun):

- `auth.spec.ts` and `secrets.spec.ts` target `data-testid`s
  (`email-input`, `password-input`, `login-button`, `create-secret-button`, …)
  that **exist nowhere in the current source** — they predate the UI refactor.
- They drive a real login (`password123` → `/dashboard`) but there is **no API
  mocking** (no MSW, no `page.route`) and `webServer` runs only the frontend
  (`npm run dev`), so the auth/secrets flows can't pass.
- `example.spec.ts` (title / viewport / `#root` smoke checks) is backend-free
  and would likely still pass.

Rewrite as part of / alongside the shadcn rewrite: add stable `data-testid`s to
the new components and a mock backend (MSW or `page.route`) or a seeded test
environment. Until then `test:e2e` is not wired into CI (CI runs the unit gate
only). Vite dev server is on port 3000, matching the Playwright `baseURL`.

## Formatting / Prettier (not enforced — deliberate)

The repo's house style is **4-space indentation + single quotes**, but there is
**no `.prettierrc`** and the codebase has never been Prettier-formatted to its
own style. Prettier's defaults (2-space, double quotes) would rewrite all ~131
files.

- Prettier is kept current as a devDependency (v3) but `format` is **not** run.
- If/when we want enforced formatting, do it deliberately as its own focused
  effort: add `.prettierrc` matching the house style (`tabWidth: 4`,
  `singleQuote: true`, and a `printWidth` chosen to minimize churn), run
  `format` once, and commit it standalone. Coordinate timing with the shadcn
  rewrite and avoid colliding with in-flight branches.

## Dependency maintenance

The upgrade campaign is **complete** — `pnpm outdated` is empty.

- Removed as dead (declared but imported nowhere): **`date-fns`**, **`jest-axe`**.
  Re-add at latest only when actually used (jest-axe with the a11y tests above).
- TypeScript is on 6.x; `tsconfig` was modernized (`moduleResolution: bundler`,
  no `baseUrl`) so it is clean for the eventual TS 7.

## Known latent issues (not failures — gate is green)

- **`utils/auth.ts` dead code + dormant bug.** Four exports are never called by
  the app: `getPersistedAuthData`, `hasRememberMe`, `getCurrentAuthState`,
  `shouldRestoreSession`. `shouldRestoreSession` also has a latent logic bug —
  it computes `sessionAge = now - expiresAt`, but `getPersistedAuthData` already
  filters expired tokens, so `expiresAt` is always in the future and the 24h
  `maxSessionAge` cap never restricts a non-remember-me session. Harmless while
  unused; decide delete-vs-fix before wiring session restore. Tracked in the
  global `keyorix-private/keyorix-backlog.md` (Codebase / Technical Debt).

## Working agreement (how changes land here)

Conventions established over the recent maintenance arc:

- Keep the green gate between every change: `type-check`, `lint` (0 errors;
  warnings under the 40 cap), `build`, `test`.
- One focused commit per logical change; dependency bumps isolated so any
  fallout is easy to attribute.
- Surface surprising findings (e.g. a "format-only" bump that turns out to
  rewrite the whole repo) rather than pushing through them.
