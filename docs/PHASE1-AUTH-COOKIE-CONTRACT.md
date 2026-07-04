# Phase 1: access-token-as-httpOnly-cookie backend contract

Drafted 2026-07-04 as a spec; **Phases A and B were implemented and fully
verified 2026-07-05** (same person owns both repos, so the sequencing below
was executed rather than handed off). See the plan file
`/Users/abeshkov/.claude/plans/iterative-cooking-sifakis.md` for the final
approved plan and `docs/PHASE0-AUDIT-FINDINGS.md`'s corrections for the
grounding facts (there were never any cookies in this system before this).

**Status**:
- Phase A (backend: cookies + CSRF + dual-accept, additive) — **done**.
- Phase B (frontend: switch to cookie auth, drop client-held token) — **done**.
- Impersonation redesign (`OriginalSessionID` server-side session-swap) — **done**.
- Bundled aside: `RevokeSessions` missing self-action guard — **fixed**.
- Phase C (remove Bearer-fallback + JSON-body token) — **not started**,
  deliberately: it's gated on "Phase B frontend is the only deployed build for
  a full max-session lifetime," an operational condition to observe in
  production, not something to do in the same sitting as A/B.

Verified: full green gate both repos (`go build`/`golangci-lint`/`go test ./...`
in keyorix; `type-check`/`lint`/`build`/`pnpm test --run` in keyorix-web), plus
live HTTP round-trip tests with real cookie jars proving: login sets both
cookies with correct attributes, cookie-only auth works, Bearer-only still
works (dual-mode), the cookie wins when both are present, CSRF is
rejected/accepted correctly, and the full impersonation start→act→end round
trip restores the *same* original session (not a fresh one) with the client
never touching a token value at any point.

The rest of this document is the original spec, kept as-written for the
Phase C follow-up and as a record of the design reasoning.

## Why this needs backend coordination first

This repo can't do this alone: the token has to stop being *returned* by the
backend before the frontend can stop *storing* it. Shipping the frontend half
first (stop reading `response.token`) breaks login outright; shipping it after
the backend switches over silently means every existing session's token is
suddenly unusable. This has to land as one coordinated cutover, not two
independent changes.

## Current state (grounds for this contract — not guesswork)

- The **refresh token is already an httpOnly cookie**, never returned in any
  JSON response body (confirmed: `LoginResponse`/`RefreshTokenResponse` in
  `src/types/index.ts` carry no refresh-token field; `services/client.ts`/
  `services/auth.ts` both set `withCredentials: true`). This decision is
  already made and working — Phase 1 is only about the **access token**.
- The **access token** is returned in the JSON body on login/refresh/SSO/setup
  (`src/services/auth.ts`), stored in Zustand + `localStorage` (`auth-storage`
  key, `src/store/authStore.ts`), and manually attached as
  `Authorization: Bearer <token>` on every request (`src/services/client.ts`,
  and separately, hand-parsed from `localStorage` in `src/services/auth.ts`'s
  own axios instance — the "two token-read implementations" LOW finding from
  Phase 0, which this migration would resolve as a side effect).
- Expiry bookkeeping (`tokenExpiresAt`, `absoluteExpiresAt`) is **already
  stored client-side separately from the token itself**, in flat
  `localStorage` keys written by `src/utils/auth.ts` — not decoded from the
  JWT. This matters: the proactive-refresh scheduling logic
  (`shouldRefreshToken`, `getProactiveRefreshDelay`, `isTokenValid` in
  `utils/auth.ts`) needs almost no change under this migration, **as long as
  the backend keeps sending `expires_at`/`absolute_expires_at` as plain JSON
  fields** even once the token value itself moves into a cookie.
- Impersonation (`src/store/authStore.ts`) currently holds **two** tokens
  client-side at once (the impersonated target's, active; the admin's own,
  stashed) — as of the 2026-07-04 fix, the admin's stashed token is in-memory
  only (never persisted), specifically to shrink its exposure window. Cookies
  change this shape entirely — see "Impersonation redesign" below, the one
  part of this contract that's a real design question, not just a mechanical
  swap.
- CORS is a non-issue here: the SPA and API are same-origin through the same
  nginx (fixed 2026-07-04, see `docs/PHASE0-AUDIT-FINDINGS.md` H1) — no
  cross-origin cookie/CORS interaction to design around.

## Proposed cookie contract

**Cookie**: `access_token` (name illustrative — match whatever convention the
refresh-token cookie already uses).
**Attributes**: `HttpOnly; Secure; SameSite=Lax; Path=/`. `Lax` over `Strict`:
`Strict` would silently drop the cookie on a top-level cross-site navigation
into the app (e.g. a bookmarked link, an email link), forcing an extra
failed-profile-check round trip before the user is prompted to log in again —
`Lax` avoids that UX regression and still blocks the classic cross-site
`<form>` POST CSRF vector. `Max-Age`/`Expires` mirrors `expires_at`.

**Per-endpoint changes**:

| Endpoint | Today | Under this contract |
|---|---|---|
| `POST /auth/login` | `{token, expires_at, absolute_expires_at, user_id, ...}` in body | Same body **minus `token`**; `Set-Cookie: access_token=...` on the response |
| `POST /auth/refresh` | `{token, expires_at, absolute_expires_at}` in body | Same body **minus `token`**; `Set-Cookie: access_token=...` (rotated value) |
| `POST /auth/logout` | Server invalidates session; client drops local token | Server invalidates session; response also sets `Set-Cookie: access_token=; Max-Age=0` — **the server clears the cookie**, not just the client |
| `GET /api/v1/auth/profile` | Reads `Authorization: Bearer` header | Reads the cookie (browser attaches it automatically) — **no client change needed here** beyond dropping the header |
| `POST /api/v1/admin/impersonate` | Returns `{token, impersonated_by, ...}` in body, client swaps `Authorization` header value | See "Impersonation redesign" — this one isn't a mechanical swap |
| `POST /api/v1/auth/end-impersonation` | Client sends the impersonation token as Bearer; server logs + drops that session | See "Impersonation redesign" |
| SSO callback (OIDC redirect landing) | Backend redirects to SPA with `#token=...&expires_at=...` in the URL **fragment** (deliberately never sent to any server/Referer) | Backend sets `Set-Cookie: access_token=...` directly on its own redirect response instead — **strictly more secure than today**: the token never touches the URL, the SPA, or JS at all. `SSOCompletePage.tsx` then just needs `expires_at`/`absolute_expires_at`/`return_to` in the fragment (no `token`) and calls `checkAuth()` once mounted, relying on the cookie the redirect already set |
| Setup-link consume (ADR-028, "complete setup") | `LoginResponse`-shaped body with `token` | Same shape minus `token`; `Set-Cookie` on that response (this is a same-origin `fetch`/XHR from the SPA, not a browser redirect, so `withCredentials: true` — already set — is sufficient for the cookie to be accepted) |

## CSRF protection — new requirement this contract introduces

Today, requiring a custom `Authorization: Bearer` header is itself an
incidental CSRF defense (a foreign origin's simple cross-site form/no-CORS
request can't set that header). Moving to an ambient cookie removes that
incidental protection, so this contract needs to add real CSRF protection for
every state-changing (non-`GET`) request:

- **Double-submit cookie pattern**: backend also sets a second,
  **non-HttpOnly** cookie (e.g. `csrf_token`) whose value the SPA reads with
  JS and echoes back as a custom header (e.g. `X-CSRF-Token`) on every
  `POST`/`PUT`/`PATCH`/`DELETE`. Server rejects the request if the header is
  missing or doesn't match the cookie. This needs no server-side session
  storage of nonces and is the standard pattern for this exact situation.
- `SameSite=Lax` on `access_token` already blocks the simplest cross-site
  `<form>` POST attack independently — the CSRF token is defense-in-depth for
  same-site-adjacent scenarios (a compromised subdomain, an XHR/fetch-based
  attack `Lax` doesn't cover), not the only layer.

## Impersonation redesign — the one real design question here

The current client-side "stash the admin's token, swap in the target's,
restore on end" model (`startImpersonation`/`endImpersonation` in
`authStore.ts`) doesn't translate to httpOnly cookies at all: JS can't read an
httpOnly cookie's value, so there is nothing for the client to "stash." This
needs a genuine backend design decision, not a mechanical translation:

**Proposed**: make impersonation a server-side session concept.
`POST /api/v1/admin/impersonate` sets a **new** `access_token` cookie value
that the server's session store resolves to "acting as user Z, on behalf of
admin session Y" — the server remembers the admin's original session
server-side (it already must track *something* to log the
`impersonation.start`/`.end` audit events, per the existing endpoints — this
just extends that to "and which cookie/session to restore"). `POST
/api/v1/auth/end-impersonation` then looks up the stashed admin session
server-side and issues a **fresh** `Set-Cookie` restoring it — the client
never needs to hold or send back an admin credential at all. This is strictly
better than the current client-side stash-and-restore (which is why the
2026-07-04 mitigation — moving `adminToken` to in-memory-only — was explicitly
framed as a stopgap, not the end state): the admin's credential never leaves
the server's session store during impersonation, closing the "double token
exposure" finding at the root instead of narrowing its window.

This is the part of Phase 1 that needs actual backend session-store design
work (does the session store already support "this session was derived from
that session, restore on end" as a concept, or does it need building?) — flag
it early with whoever owns the Go backend, since it's likely the
longest-lead-time piece of this contract.

## Frontend-side scope, for estimating the Phase 1 pass

Once the above lands backend-side, the frontend changes are mostly deletions:

- Remove `token` from `AuthStore`'s persisted/in-memory state and from
  `LoginResponse`/`RefreshTokenResponse` types; remove every
  `Authorization: Bearer` header-setting call in `services/client.ts` and
  `services/auth.ts` (the two-implementations LOW finding disappears — there's
  no token to read from either place anymore).
- Keep `user`/`isAuthenticated`/expiry bookkeeping exactly as today — none of
  that is sensitive, all of it stays in Zustand/`localStorage` for display and
  scheduling purposes.
- The multi-tab `storage`-event sync added 2026-07-04 stays useful (for
  keeping `user`/`isAuthenticated` display state in sync across tabs) but
  loses its most important job — an actual cross-tab stale-token race can't
  happen once the cookie is the single source of truth shared natively by the
  browser across all tabs.
- `SSOCompletePage.tsx`: drop the `token` param entirely from the fragment
  parsing; everything else (`return_to` validation, `expires_at`) stays.
- `authStore.ts`'s impersonation actions get simpler on the client (no more
  stashing anything) once the server does the session-swap — this also
  retires the in-memory-only `adminToken`/`adminUser` mitigation from
  2026-07-04, replacing it with the real fix rather than the narrowed-window
  stopgap.
- `checkAuth()`/`refreshToken()`/route guards: essentially unchanged, since
  they already don't decode the token — they call `getProfile()`/`refresh()`
  and trust the response, same as today.

## Open questions for the backend team

1. Does the session store already have a concept of "session derived from
   another session, restorable" — or does impersonation-as-a-server-concept
   need new session-store work?
2. Confirm the refresh-token cookie's exact attributes today (name,
   `SameSite`, path) so `access_token` can match convention rather than
   introducing a second, differently-configured cookie.
3. Any existing CSRF protection on the refresh-token cookie flow today worth
   reusing for the new `access_token`/CSRF-token pair, or is this the first
   CSRF protection the API gets?
4. Rollout: can the backend support both response shapes (body token +
   cookie) simultaneously behind a flag for a transition window, or does this
   have to be an atomic cutover (coordinated deploy of backend + frontend at
   the same moment)? Given every current session would otherwise become
   invalid, a transition window (accept both, prefer cookie if present) is
   strongly preferred over a hard cutover.

## Testing/rollout notes for whenever this is picked up

- The existing `auth-integration.test.tsx`, `ProtectedRoute`/`AdminRoute`/
  `PublicRoute` test suites, and the new `multiTabSync.test.ts` /
  `impersonation.test.ts` cases added this session all currently assert on
  client-held `token` values — expect meaningful rewrites there, not just
  incremental edits, since the thing they're asserting on (a client-visible
  token) goes away.
- E2E (Playwright, currently stale per BACKLOG.md) should specifically cover
  the impersonation start/end round-trip once server-side session-swap lands
  — that's the highest-risk behavioral change in this whole contract.
