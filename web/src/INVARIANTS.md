# web/src invariants

Read this before changing anything in `web/src`'s API/service layer (the frontend's HTTP
client code and the pages/components that drive it). This is a lightly-guarded area relative
to the Go backend — several invariants below hold today "by inspection" / architectural
omission rather than a positive mechanical check. Treat the UNGUARDED items as a priority list,
not a clean bill of health.

Format: `INV-WEB-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## API layer convention

- **INV-WEB-01** Exactly two HTTP client instances exist in `web/src`: `services/client.ts`'s
  `apiClient` (general) and `services/auth.ts`'s `authApi` (separate, to avoid a circular
  import `auth.ts → client.ts → authStore.ts → auth.ts`) — no raw `fetch(`,
  `axios.get|post|put|delete|patch(`, or `XMLHttpRequest` exists anywhere else (confirmed by
  repo-wide grep; the only other `fetch(` hits are React Query `refetch()` calls). UNGUARDED
  mechanically (#issue: no `eslint.config.mjs` rule — e.g. `no-restricted-syntax` banning raw
  `fetch`/`axios` outside these two files — enforces this; it holds today by inspection only).

## CSRF — well guarded

- **INV-WEB-02** `getCsrfToken()` reads the `csrf_token` cookie; both `apiClient` and
  `authApi` attach it as `X-CSRF-Token` on state-changing methods (`post`/`put`/`patch`/
  `delete`) only, never on GET. Guard: `services/__tests__/client.test.ts` (CSRF-header
  attach/non-attach/never-on-GET cases); `utils/__tests__/auth.test.ts`'s `getCsrfToken`
  `describe` block (3 tests).

## Auth-token storage — httpOnly cookie only

- **INV-WEB-03** The session credential itself rides an httpOnly cookie the browser attaches
  automatically — `web/src` never reads or stores the credential's value. `localStorage`
  (`utils/index.ts`'s `storage` wrapper, `main.tsx`) holds only UI preferences and expiry
  bookkeeping (`tokenExpiresAt`, `absoluteExpiresAt`), never the credential. Why: explicit
  doc comments in `services/client.ts` (lines ~41-45) and `utils/auth.ts`. UNGUARDED for the
  specific NEGATIVE invariant (#issue: no test scans `localStorage` keys for a JWT-shaped
  value / asserts "no raw session token ever reaches localStorage" — today's protection is
  architectural, via `persistAuthData` never being handed the credential, not a positive
  assertion that would catch a future regression).

## CSV writer (formula-injection, CWE-1236)

- **INV-WEB-04** The one client-side CSV export in `web/src` (`pages/audit/AuditLogPage.tsx`,
  the only `new Blob(`-based export in the whole tree) neutralizes formula injection and
  properly quotes CSV-special characters — mirrors the Go `csvSafe` encoder
  (`server/http/handlers/csv_safe.go`) explicitly cited in its own comment. Guard:
  `pages/audit/__tests__/AuditLogPage.test.tsx` (`'neutralizes formula-injection and properly
quotes CSV-special characters...'`). See `internal/core/INVARIANTS.md` INV-CORE-39 for the
  Go-side half of this same class — if a second client-side CSV writer is ever added, it needs
  the identical treatment and an identical test.

## OpenAPI contract drift — guarded for the schema'd wire types

- **INV-WEB-05** The wire-shaped types in `web/src/types` (`index.ts`, `rbac.ts`) stay in sync
  with the server's OpenAPI contract (`server/http/handlers/openapi.yaml`, ADR-074): field
  names in both directions, JSON kind, nullability, enums, and optionality where the schema
  declares `required`. Contrast `cli/`, whose `internal/apiclient/*.gen.go` is generated from
  the same spec. Web is checked, not generated, because `web/src/types` mixes wire types with
  UI models the services layer builds by mapping (`User`, `Secret`, `ShareRecord`,
  `DashboardStats`, ...), and about half the endpoints web calls have only a prose 200
  description in the spec, so there is nothing to generate from. Guard:
  `types/__tests__/openapiDrift.test.ts` (real spec; also a partition — every exported
  interface is in `WIRE_TYPES` or in `NOT_COMPARED` with a reason — and a stale-exemption
  check) and `types/__tests__/openapiDrift.engine.test.ts` (calibration: the engine is red on
  each drift class, green on a match). **Not covered**: the `NOT_COMPARED` types; wire bodies
  `services/*.ts` reads as `any` (a misspelled key there is invisible); endpoints with no
  response schema in the spec (`SecretPolicy`, `SecretUsageStat`, `UnusedSecretStat`,
  `RotationStatusEntry`, the profile `impersonation` object — add the schema to the spec,
  then move the type into `WIRE_TYPES`). **CI gap**: `.github/workflows/web-ci.yml` is
  path-filtered to `web/**`, so a PR that edits only `openapi.yaml` does not run this guard
  until the next web change or the Sonar coverage run; adding
  `server/http/handlers/openapi.yaml` to that workflow's `paths` closes it (needs a
  `.github/**` change).

## Anti-enumeration — holds by omission, not by a guard

- **INV-WEB-06** The frontend does not currently leak a resource's existence via differential
  rendering of "doesn't exist" vs. "exists but forbidden" — confirmed by grep: zero frontend
  code branches on `status === 404` specifically anywhere in `web/src`; generic error handling
  (`handleApiError`/`apiErrorMessage`) treats non-2xx uniformly except for a few explicit
  401/403/429/5xx branches aimed at session/permission UX (none of which are per-resource
  existence distinctions). This holds because no code path TRIES to distinguish 404 from 403
  at all, not because of a deliberate guard. UNGUARDED (#issue: no test asserts this invariant
  — if a future PR adds a 404-specific UI branch for some resource, nothing catches it reopening
  an existence oracle that the backend's ADR-096 403-for-both convention was built to close).

## Structural completeness — none found

- **INV-WEB-07** No structural/completeness test exists in `web/src` analogous to the Go
  backend's AST sweeps (e.g. nothing asserts "every service file uses `apiClient`" or "every
  mutating page attaches CSRF" as a repo-wide check rather than a per-file unit test).
  `__tests__/App.test.tsx`, `constants.test.ts`, `test/infrastructure.test.ts` are component/
  unit/smoke tests, not sweeps. UNGUARDED as a class (#issue: the lowest-effort version would be
  an ESLint custom rule or a small Node script walking `web/src/services` and `web/src/pages`
  rather than a hand-maintained convention).
