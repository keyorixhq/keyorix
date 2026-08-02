# Features

One folder per domain. Each folder owns:

- `api.ts` — TanStack Query hooks (the data layer for this feature)
- `<Component>.tsx` — components specific to this feature
- `use<X>.ts` — composite hooks that combine api hooks with UI state (filters, pagination, modal control)

## Rules

- Components and pages import from `features/<domain>/`. They do NOT import from `services/`.
- `features/<domain>/api.ts` imports from `services/<domain>` (the per-domain API module).
- Only `services/client.ts` touches axios. Nothing else.
- New feature → new folder. Do not add cross-feature shared logic without an explicit reason.

## Hook patterns

- **Thin data hooks** (`api.ts`): one query or mutation per export, no UI state. Reusable across pages.
- **Composite hooks** (`use<X>.ts`): wrap thin hooks and add UI state (filters, pagination, modal control). Used by one specific page.

## Phase 3 conventions (May 2026)

- **Flat layout**: components live at the root of `features/<domain>/`. No `components/` subfolder inside a feature unless it has 5+ components.
- **Public API via index.ts**: every feature folder exposes an `index.ts`. Pages and other features import only from `features/<domain>` (the index), never from deep paths like `features/<domain>/api` or `features/<domain>/ComponentName`.
- **Auth lives in `features/auth/`**: `LoginForm`, `PasswordResetForm`, and `useAuth` are all in `features/auth/`. The old `hooks/` and `components/forms/` directories are gone.
- **`components/` is cross-cutting only**: after Phase 3, `src/components/` contains only `layout/`, `providers/`, and `ui/` — code shared across the entire app. Feature-specific components belong in their feature folder.
- **`services/auth.ts` stays under `services/`**: all axios calls must live in `services/`. `features/auth/api.ts` (useAuth) wraps Zustand, not axios.

## Domains

| Folder       | index.ts exports                                                                                                                                                                                          | Notes                                                            |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `secrets/`   | api hooks + SecretDetailView, SecretTableRow, useSecretsList, useSecretReveal                                                                                                                             | composite hooks at root                                          |
| `dashboard/` | api hooks (useDashboardStats, useDashboardActivity, useSystemInfo, useSystemMetrics, useAuthConfig, useEncryptionConfig, useAnomalyAlerts, useAcknowledgeAnomaly, useUsers, useUser, useGroups, useGroup) |                                                                  |
| `admin/`     | api hooks (useAdminStats, useAdminUsers, useAdminRoles, useAdminAuditLogs, useAdminUserList, useAdminCreateUser, useAdminUpdateUser, useAdminDeleteUser)                                                  |                                                                  |
| `audit/`     | api hooks (useAuditLog)                                                                                                                                                                                   |                                                                  |
| `sharing/`   | api hooks + ShareSecretModal                                                                                                                                                                              |                                                                  |
| `auth/`      | useAuth, LoginForm, PasswordResetForm                                                                                                                                                                     | wraps Zustand authStore; forms moved here from components/forms/ |
