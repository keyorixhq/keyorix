# keyorix-web — refactor candidates (cyclomatic complexity)

Functions with cyclomatic complexity (CCN) above 15, found via [`lizard`](https://github.com/terryyin/lizard) (`lizard -w -C 15 -L 1000000 -a 1000 ...`, CCN-only — length/param-count warnings suppressed). Generated 2026-07-30.

**Read this as a worklist, not a mandate.** High CCN correlates with more test paths and higher change risk, but the shape matters more than the number: a long sequential migration chain or a field-by-field `normalize*()` mapper can have a very high CCN while being low-risk (each branch is independent, not nested, and rarely touched together). Prioritize functions that *mix unrelated concerns* in one place over ones that are just long dispatch/mapping tables — and refactor opportunistically, when you are already touching the function for a feature or bugfix, rather than as a dedicated sweep.

| CCN | Function | Location | NLOC | Params |
|----:|----------|----------|-----:|-------:|
| 115 | `buildCreateModalContent` | `src/pages/admin/AdminPage.tsx:114` | 1160 | 1 |
| 103 | `renderExpiringSecretsSection` | `src/pages/projects/ProjectSettingsTab.tsx:439` | 793 | 5 |
| 60 | `DashboardPage` | `src/pages/dashboard/DashboardPage.tsx:270` | 208 | 0 |
| 58 | `SecretsListPage` | `src/pages/secrets/SecretsListPage.tsx:149` | 756 | 0 |
| 57 | `normalizeAccessRequest` | `src/services/projectInvitations.ts:50` | 14 | 1 |
| 55 | `normalizeConfig` | `src/services/dynamicSecrets.ts:80` | 13 | 1 |
| 53 | `ScoreRing` | `src/pages/secrets/SecretsHealthPage.tsx:42` | 453 | 1 |
| 52 | `SecurityTab` | `src/pages/profile/ProfilePage.tsx:136` | 499 | 0 |
| 49 | `normalizeMachineIdentity` | `src/services/machineIdentities.ts:52` | 14 | 1 |
| 46 | `ProjectSecretsTab` | `src/pages/projects/ProjectSecretsTab.tsx:38` | 595 | 1 |
| 46 | `normalizeRole` | `src/services/rbac.ts:7` | 21 | 1 |
| 45 | `AuditLogPage` | `src/pages/audit/AuditLogPage.tsx:820` | 171 | 0 |
| 41 | `normalizeAccessReviewEntry` | `src/services/projects.ts:69` | 14 | 1 |
| 39 | `normalizeLease` | `src/services/dynamicSecrets.ts:94` | 11 | 1 |
| 39 | `normalize` | `src/services/projects.ts:278` | 12 | 1 |
| 37 | `normalizeMembership` | `src/services/projectMemberships.ts:30` | 10 | 1 |
| 37 | `normalizeInvitation` | `src/services/projectInvitations.ts:39` | 10 | 1 |
| 35 | `MachineIdentitiesSection` | `src/features/machine-identities/MachineIdentitiesSection.tsx:57` | 207 | 1 |
| 35 | `copyLink` | `src/pages/admin/UserDetailPage.tsx:207` | 288 | 0 |
| 35 | `normalizeItem` | `src/services/projects.ts:142` | 13 | 1 |
| 35 | `(anonymous)` | `src/services/secrets.ts:79` | 19 | 0 |
| 33 | `normalizeToken` | `src/services/machineIdentities.ts:90` | 10 | 1 |
| 31 | `MachineTokensPanel` | `src/features/machine-identities/MachineTokensPanel.tsx:20` | 152 | 3 |
| 30 | `SharingManagementPage` | `src/pages/sharing/SharingManagementPage.tsx:75` | 442 | 0 |
| 28 | `ProjectAccessReviewTab` | `src/pages/projects/ProjectAccessReviewTab.tsx:45` | 166 | 1 |
| 28 | `RolesPoliciesPage` | `src/pages/admin/RolesPoliciesPage.tsx:114` | 264 | 0 |
| 25 | `AccessRequestRow` | `src/features/invitations/PendingAccessRequestsSection.tsx:77` | 124 | 3 |
| 25 | `normalizeCampaign` | `src/services/projects.ts:126` | 8 | 1 |
| 23 | `issue` | `src/services/dynamicSecrets.ts:139` | 13 | 2 |
| 23 | `issueToken` | `src/services/machineIdentities.ts:151` | 19 | 3 |
| 21 | `GroupsPage` | `src/pages/admin/GroupsPage.tsx:119` | 220 | 0 |
| 21 | `(anonymous)` | `src/services/projects.ts:251` | 12 | 0 |
| 21 | `normalizeControl` | `src/services/compliance.ts:158` | 14 | 1 |
| 21 | `normalizeException` | `src/services/compliance.ts:196` | 10 | 1 |
| 19 | `DynamicSecretsPage` | `src/pages/secrets/DynamicSecretsPage.tsx:33` | 138 | 0 |
| 19 | `normalizeMember` | `src/services/projects.ts:269` | 8 | 1 |
| 18 | `SecretDependenciesSection` | `src/features/secrets/SecretDependenciesSection.tsx:17` | 95 | 1 |
| 18 | `ProjectAccessReviewCampaigns` | `src/pages/projects/ProjectAccessReviewCampaigns.tsx:51` | 101 | 1 |
| 18 | `parseUptime` | `src/pages/dashboard/DashboardPage.tsx:25` | 18 | 1 |
| 18 | `eventBadge` | `src/pages/audit/AuditLogPage.tsx:182` | 20 | 2 |
| 17 | `React.FC` | `src/features/account/MfaSection.tsx:252` | 108 | 0 |
| 17 | `normalizeViolation` | `src/services/compliance.ts:133` | 7 | 1 |
| 17 | `(anonymous)` | `src/services/users.ts:173` | 6 | 0 |
| 16 | `CampaignDetail` | `src/pages/projects/ProjectAccessReviewCampaigns.tsx:197` | 140 | 3 |
| 16 | `(anonymous)` | `src/pages/admin/OIDCFederationSection.tsx:222` | 165 | 0 |

_45 functions total._
