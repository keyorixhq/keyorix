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

## Domains

| Folder | api.ts exports | Notes |
|---|---|---|
| `secrets/` | useSecrets, useSecret, useSecretVersions, useCreateSecret, useUpdateSecret, useDeleteSecret, useBulkDeleteSecrets, useDuplicateSecret, useSearchSecrets | also useSecretsList.ts (composite), useSecretReveal.ts (composite) |
| `dashboard/` | useDashboardStats, useDashboardActivity, useSystemInfo, useSystemMetrics, useAnomalyAlerts, useAcknowledgeAnomaly, useUsers, useUser, useGroups, useGroup | |
| `admin/` | useAdminStats, useAdminUsers, useAdminRoles, useAdminAuditLogs, useAdminUserList, useAdminCreateUser, useAdminUpdateUser, useAdminDeleteUser | |
| `audit/` | useAuditLog | |
| `sharing/` | useShares, useDeleteShare, useBulkDeleteShares, useCreateShare, useShareSecret, searchRecipients | |
