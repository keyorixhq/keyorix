# ADR-124: Per-user UI settings live on the server, in SQL

**Status:** Proposed (2026-11-25). Direction given by Andrei on 2026-11-25; it becomes Accepted when
he approves this text. No code follows before approval.
**Date:** 2026-11-25
**Related:** [ADR-123](adr-123-ui-teaching-one-time-page-hints.md) (page hints; their "seen" state
is the first setting stored this way).

## Decision

A user's web UI settings are stored on the server, in the database, per user. They follow the
user to any browser and device. The browser keeps only a small cache so the first screen is drawn
correctly before the server has answered. The server value wins as soon as it is known.

**One place.** Every per-user UI setting lives in this store and nowhere else. A setting is not
split between the browser, a cookie and the server. A new setting is added as a new key here; it
is never added as a new `localStorage` key. The only browser-side copy is the first-paint cache
in rule 5.

This covers, in the first version: theme, interface language, timezone, the expanded or collapsed
state of sidebar groups, the recently used projects list (ADR-018), and the "seen" state of page
hints.

## Context

Today the web application keeps its settings in the browser. The UI store persists `theme` and
`sidebarExpanded` in `localStorage` under `keyorix-ui`, and the recently used projects list
(ADR-018) is also browser-local. There is no table, model or API for user settings on the server.
The frontend declares a `UserPreferences` type (language, timezone, theme, notifications) and the
store README describes a preferences store, but neither is backed by anything: no
`preferencesStore.ts` exists, and the Go code and OpenAPI mention no user preferences. The type and
the README describe an intention, not a feature.

Browser-only storage has three costs for a product used by administrators on several machines:

- A setting does not follow the person. A new browser, a cleared profile or a private window
  shows the default theme again and every one-time hint again, which defeats the rule in ADR-123.
- Tests start from nothing in every fresh browser context and cannot put a user into a known
  state through the API.
- Nothing can be reset or inspected by an administrator, and nothing leaves with the user's data.

## Rules

1. **Server is the source of truth.** The browser cache is a copy, never the original. If the
   two differ after login, the server value is applied and the cache is updated.
2. **Storage shape.** One row per user and key, in a new table, with a server-side allowlist of
   keys. A key has a declared type and allowed values, and the server rejects anything else.
   Per-key rows, not one JSON document, so two tabs changing different settings cannot overwrite
   each other. Page hints use keys of the form `hint.<id>` holding the hint's version.
3. **Own settings only.** A user reads and writes only their own settings. There is no endpoint
   that writes another user's settings. An administrator resetting a user's settings is a
   separate, later decision.
4. **API.** One read call returning all of the caller's settings, and one write call that sets or
   clears named keys in a single request. Both are described in the OpenAPI document, and the
   generated frontend types follow it.
5. **First paint and sign-in page.** Before sign-in there is no user, so the sign-in page uses the
   cached theme, or the system theme, and the browser language. The cache holds only theme and
   language and is allowed under the storage rule in `web/src/INVARIANTS.md` (INV-WEB-03): a UI
   preference, never a credential.
6. **Failure does not block.** If a read or write fails, the UI keeps working on the cache and
   defaults, and retries the write later. A settings failure never blocks sign-in, a page or an
   action on a secret.
7. **Limits.** A bounded number of keys per user, a bounded value size, and the same rate limits
   as other authenticated writes. Values are never free text from the user, never secrets, and
   never shown in the audit log.
8. **Account state.** Settings are available once the account is fully active. In states that
   gate the account (first-login password change, required MFA enrolment) the endpoints are not
   needed and follow the same gate as the rest of the API, and the cache covers the screen.
9. **Lifecycle.** Settings are removed when the user is erased and are part of a user's own data
   if an export exists. A user suspended or soft-deleted keeps nothing that grants access, since
   a setting never grants access.
10. **One-time carry-over.** On the first sign-in after the upgrade, if the server has no value
    for a key and the browser holds one (for example the theme), the browser value is uploaded
    once, so nobody loses their theme.
11. **Same on both databases.** A plain table that works identically on SQLite and PostgreSQL,
    registered with the other models and covered by the migration guard tests.
12. **No second store.** A guard test fails the web build if code under `web/src` writes to
    `localStorage` or `sessionStorage` under a key that is not on a short allowlist (the
    first-paint cache, and the bookkeeping already allowed by INV-WEB-03 such as session expiry
    times). This is what keeps settings from spreading back across places.
13. **Audit.** Changing a setting is not a security event and is not written to the audit chain.
    This is stated here so it is a decision and not an omission; it is revisited if a setting
    ever affects what a user may see or do.

## Not in the first version

- **Notification settings** (email, browser, sharing, security). They depend on delivery
  channels with their own decisions, and the frontend type for them has no server behaviour behind
  it. When those channels exist, their per-user switches become keys in this same store, not a
  second one.
- **Deployment-wide defaults** (for example a site that wants Spanish for everyone) and
  administrator reset. Both are useful, neither is needed for the first version.
- **Anything the CLI reads.** These are web UI settings only.

## Alternatives considered

- **Keep `localStorage` and add the server later.** Rejected: every user would see every hint
  again once at the move, and the "once per user" rule would not hold in the meantime.
- **A single JSON column on the users table.** Simpler to read, but two concurrent writes can
  lose a change, every new setting changes a wide table, and it mixes UI state with account data
  that has strict rules.
- **A narrow table for hints only.** Rejected after discussion: theme and language have the same
  needs, and a second table later would be a second migration for the same idea.
- **Cookies.** Rejected: sent with every request, small, and no better than the server for
  following the person.

## Open decisions

- The exact key names, types and allowed values for the first version, and the limits.
- Whether the interface language needs a translation mechanism first. No i18n library is in the
  web application today, so a language key is only useful once strings can be translated.
- How the recently used projects list is stored: it changes on every visit, so writes must be
  batched or delayed, and the value needs a size bound.
- Administrator reset and deployment-wide defaults, as above.

## Consequences

A new table, two API calls, OpenAPI and generated types, a settings layer in the web store that
reads on sign-in and writes through, the browser-storage guard test from rule 12, and tests for the
carry-over, for failure without blocking, and for refusing other users' settings. The sidebar
state and the recent projects list move from the browser into the store. The `UserPreferences` type and the README section on a
preferences store are replaced by what this ADR describes. Nothing changes until it is approved.
