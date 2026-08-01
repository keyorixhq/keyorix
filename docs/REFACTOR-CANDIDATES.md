# keyorix-web — refactor candidates (cyclomatic complexity)

**Regenerated 2026-08-01 — the 2026-07-30 version of this doc was wrong.** It
was generated with [`lizard`](https://github.com/terryyin/lizard)
(`lizard -w -C 15 -L 1000000 -a 1000`), which does naive brace-counting to
find function boundaries — and JSX's `{expr}` interpolation isn't a code
block, it just looks like one to a brace-counter. That made lizard massively
misjudge JSX-returning functions' boundaries (and therefore their line counts
and complexity): the two "worst offenders" it reported,
`buildCreateModalContent` (claimed CCN 115, 1160 lines) and
`renderExpiringSecretsSection` (claimed CCN 103, 793 lines), are actually 250
and ~70 lines with real cyclomatic complexity of **12** and **4** —
i.e. neither belongs on this list at all. Plain-TypeScript `normalize*()`
mapper functions (no JSX, no ambiguous braces) were unaffected and are
essentially unchanged between the two versions.

This version uses ESLint's core `complexity` rule instead (real AST via
`typescript-eslint`'s parser, correctly JSX-aware — the same parser
`pnpm lint` already uses). One-off local audit, not part of the committed
lint config:

```
pnpm exec eslint src --rule '{"complexity": ["warn", 1]}' --format json
```

then filtered to `complexity >= 15` and sorted descending.

**Read this as a worklist, not a mandate.** High complexity correlates with
more test paths and higher change risk, but the shape matters more than the
number: a long sequential migration chain or a field-by-field
`normalize*()` mapper can have a high score while being low-risk (each
branch is independent, not nested, and rarely touched together). Prioritize
functions that *mix unrelated concerns* in one place over ones that are just
long dispatch/mapping tables or large-but-flat page components — and refactor
opportunistically, when you are already touching the function for a feature
or bugfix, rather than as a dedicated sweep.

| CCN | Function / Component | Location |
|----:|----------|----------|
| 70 | `DashboardPage` | `src/pages/dashboard/DashboardPage.tsx:273` |
| 61 | `SecretsListPage` | `src/pages/secrets/SecretsListPage.tsx:149` |
| 51 | `SecretDetailView` | `src/features/secrets/SecretDetailView.tsx:170` |
| 47 | `ProjectSecretsTab` | `src/pages/projects/ProjectSecretsTab.tsx:38` |
| 46 | `AdminPage` | `src/pages/admin/AdminPage.tsx:611` |
| 42 | `normalize` (compliance posture) | `src/services/compliance.ts:65` |
| 42 | `ServiceAccountsPage` | `src/pages/admin/ServiceAccountsPage.tsx:194` |
| 40 | `UserDetailPage` | `src/pages/admin/UserDetailPage.tsx:93` |
| 35 | `ProjectSettingsTab` | `src/pages/projects/ProjectSettingsTab.tsx:714` |
| 35 | `AuditLogPage` | `src/pages/audit/AuditLogPage.tsx:862` |
| 31 | `dynamicSecretsApi` object method | `src/services/dynamicSecrets.ts:80` |
| 30 | `machineIdentitiesApi` object method | `src/services/machineIdentities.ts:52` |
| 29 | `projectInvitationsApi` object method | `src/services/projectInvitations.ts:50` |
| 29 | `SharingManagementPage` | `src/pages/sharing/SharingManagementPage.tsx:75` |
| 27 | `GroupsPage` | `src/pages/admin/GroupsPage.tsx:126` |
| 26 | `ProjectsListPage` | `src/pages/projects/ProjectsListPage.tsx:242` |
| 26 | `RolesPoliciesPage` | `src/pages/admin/RolesPoliciesPage.tsx:118` |
| 22 | `dynamicSecretsApi` object method | `src/services/dynamicSecrets.ts:94` |
| 22 | `TokensTab` | `src/pages/profile/ProfilePage.tsx:326` |
| 22 | `normalizePolicy` | `src/features/secrets/useRotationPolicies.ts:13` |
| 21 | `projectsApi` object method | `src/services/projects.ts:69` |
| 20 | `projectsApi` object method (`normalize`) | `src/services/projects.ts:278` |
| 20 | `OIDCFederationSection` | `src/pages/admin/OIDCFederationSection.tsx:124` |
| 20 | `queryFn` (async) | `src/features/audit/api.ts:24` |
| 19 | `projectMembershipsApi` object method | `src/services/projectMemberships.ts:30` |
| 19 | `projectInvitationsApi` object method | `src/services/projectInvitations.ts:39` |
| 18 | `secretsApi.list` mapper | `src/services/secrets.ts:79` |
| 18 | `projectsApi` object method | `src/services/projects.ts:142` |
| 17 | `machineIdentitiesApi` object method | `src/services/machineIdentities.ts:90` |
| 17 | `ShareSecretModal` | `src/features/sharing/ShareSecretModal.tsx:54` |
| 17 | `MfaSection` | `src/features/account/MfaSection.tsx:262` |
| 16 | `projectsApi` object method | `src/services/projects.ts:197` |
| 16 | `normalizeControl` | `src/services/compliance.ts:158` |
| 16 | `RotationPoliciesPage` | `src/pages/secrets/RotationPoliciesPage.tsx:98` |
| 16 | `SecretsRotationPlanPanel` | `src/pages/projects/SecretsRotationPlanPanel.tsx:38` |
| 16 | `RefGrantsPanel` | `src/pages/integrations/KeyorixConnectPage.tsx:185` |
| 16 | `MachineIdentitiesSection` | `src/features/machine-identities/MachineIdentitiesSection.tsx:117` |
| 16 | `Select` | `src/components/ui/Select.tsx:21` |
| 15 | `SecretsDriftPanel` | `src/pages/projects/SecretsDriftPanel.tsx:27` |
| 15 | `FederatedReadPanel` | `src/pages/integrations/KeyorixConnectPage.tsx:42` |
| 15 | `eventBadge` | `src/pages/audit/AuditLogPage.tsx:182` |
| 15 | `useSecretsHealth` | `src/features/secrets/useSecretsHealth.ts:23` |
| 15 | `AccessRequestRow` | `src/features/invitations/PendingAccessRequestsSection.tsx:79` |

_43 functions/components total (was 45 under the broken methodology — a
near-identical count, but almost entirely different functions in a
different order)._

## Reading this list

The pattern is now much clearer than the old one: the real top offenders are
almost all **large page-level components** (`DashboardPage`,
`SecretsListPage`, `ProjectSecretsTab`, `AdminPage`, `ServiceAccountsPage`,
`UserDetailPage`, `ProjectSettingsTab`, `AuditLogPage`, ...) — a lot of
hooks, local state, and conditional rendering in one function body, which is
exactly the "mixes unrelated concerns" shape worth breaking up opportunistically.
The `normalize*()` / API-object-method entries are the same low-risk
field-mapping code called out in the original doc's guidance — not worth a
dedicated pass.
