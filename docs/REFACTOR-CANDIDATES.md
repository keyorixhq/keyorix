# keyorix — refactor candidates (cyclomatic complexity)

Functions with cyclomatic complexity (CCN) above 15, found via [`lizard`](https://github.com/terryyin/lizard) (`lizard -w -C 15 -L 1000000 -a 1000 ...`, CCN-only — length/param-count warnings suppressed). Generated 2026-07-30.

**Read this as a worklist, not a mandate.** High CCN correlates with more test paths and higher change risk, but the shape matters more than the number: a long sequential migration chain or a field-by-field `normalize*()` mapper can have a very high CCN while being low-risk (each branch is independent, not nested, and rarely touched together). Prioritize functions that *mix unrelated concerns* in one place over ones that are just long dispatch/mapping tables — and refactor opportunistically, when you are already touching the function for a feature or bugfix, rather than as a dedicated sweep.

| CCN | Function | Location | NLOC | Params |
|----:|----------|----------|-----:|-------:|
| 182 | `migrateDatabase` | `internal/storage/factory.go:569` | 542 | 1 |
| 108 | `initializeCoreService` | `server/main.go:252` | 448 | 1 |
| 59 | `ListSecrets` | `server/http/handlers/secrets_list.go:43` | 214 | 2 |
| 40 | `runScan` | `internal/cli/secret/scan.go:102` | 109 | 2 |
| 33 | `startHTTPServer` | `server/main.go:860` | 182 | 2 |
| 28 | `ActivateBreakGlass` | `internal/core/break_glass.go:62` | 97 | 5 |
| 28 | `CreateSecret` | `internal/core/secrets.go:66` | 88 | 2 |
| 28 | `GetAuditLogs` | `server/http/handlers/audit.go:53` | 95 | 2 |
| 27 | `Validate` | `internal/config/config.go:1668` | 60 | 0 |
| 24 | `Validate` | `internal/core/password_policy.go:50` | 45 | 2 |
| 24 | `CreateUser` | `server/grpc/services/user_service.go:36` | 69 | 2 |
| 23 | `verifyAccessReviewGrantExists` | `internal/core/access_review_revoke.go:164` | 53 | 3 |
| 23 | `targetEncryptionConfig` | `internal/cli/encryption/migrate_provider.go:243` | 64 | 2 |
| 22 | `BootstrapSystem` | `internal/core/auth_bootstrap.go:185` | 98 | 2 |
| 22 | `(anonymous)` | `server/http/handlers/scim_groups.go:220` | 71 | 1 |
| 21 | `CompleteSAML` | `internal/core/sso.go:304` | 63 | 6 |
| 21 | `UpdateUser` | `internal/core/users.go:261` | 55 | 2 |
| 21 | `(anonymous)` | `internal/core/dynamic_secrets.go:734` | 68 | 1 |
| 21 | `runCreate` | `internal/cli/user/create.go:56` | 76 | 2 |
| 21 | `runReview` | `internal/cli/request/review.go:43` | 69 | 2 |
| 21 | `(anonymous)` | `internal/storage/store/local_audit.go:326` | 71 | 1 |
| 21 | `GenerateUpstream` | `internal/rotation/awsiam.go:72` | 72 | 2 |
| 21 | `ListUsers` | `server/http/handlers/users_list.go:30` | 67 | 2 |
| 20 | `ListSecretsWithSharingInfo` | `internal/core/secret_listing_query.go:73` | 86 | 3 |
| 20 | `ListSecrets` | `internal/storage/store/local_secrets.go:600` | 67 | 2 |
| 19 | `BulkRenameSecrets` | `internal/core/secret_bulk_rename.go:60` | 69 | 8 |
| 19 | `(anonymous)` | `internal/cli/audit/audit.go:221` | 69 | 2 |
| 18 | `sweepSecretVersions` | `internal/encryption/sweep.go:127` | 74 | 5 |
| 18 | `CheckSecretPermission` | `internal/core/permissions.go:63` | 70 | 4 |
| 18 | `ReconcileRBACPermissions` | `internal/core/rbac_reconcile.go:23` | 62 | 1 |
| 18 | `buildShareDetails` | `internal/core/secret_listing_sharing.go:217` | 60 | 1 |
| 18 | `ResolveRemote` | `internal/cli/common/remote_client.go:34` | 34 | 0 |
| 18 | `validateFilePermissions` | `internal/startup/validation.go:104` | 74 | 4 |
| 17 | `ValidateSessionToken` | `internal/core/auth.go:439` | 41 | 2 |
| 17 | `SendRotationReminders` | `internal/core/rotation_reminders.go:27` | 58 | 1 |
| 17 | `SendExpiryReminders` | `internal/core/expiry_reminders.go:30` | 59 | 2 |
| 17 | `SetSecretAutoRotate` | `internal/core/rotation_executor.go:594` | 55 | 4 |
| 17 | `(anonymous)` | `internal/core/dynamic_secrets.go:399` | 76 | 1 |
| 17 | `runGetEmbedded` | `internal/cli/secret/get.go:159` | 62 | 1 |
| 17 | `CreateGlobalInvitation` | `server/http/handlers/invitations.go:93` | 61 | 2 |
| 16 | `CompleteSSO` | `internal/core/sso.go:184` | 56 | 6 |
| 16 | `completeInvitationAccept` | `internal/core/setup_consume.go:161` | 62 | 5 |
| 16 | `InviteGlobal` | `internal/core/invitations.go:168` | 68 | 5 |
| 16 | `ScanCertificateExpiry` | `internal/core/certificate_expiry.go:35` | 53 | 2 |
| 16 | `BuildSecretUpdateDiff` | `internal/core/audit_diff.go:30` | 34 | 3 |
| 16 | `migrateProviderWithConfig` | `internal/cli/encryption/migrate_provider.go:334` | 65 | 3 |
| 16 | `runInit` | `internal/cli/system/init.go:76` | 38 | 2 |
| 16 | `buildAuditLogQuery` | `internal/cli/audit/audit.go:397` | 36 | 0 |
| 16 | `interactiveUpdate` | `internal/cli/secret/update.go:239` | 57 | 1 |
| 16 | `(anonymous)` | `internal/cli/secret/scan.go:159` | 40 | 3 |
| 16 | `CreateShareRecord` | `internal/storage/store/local_sharing.go:26` | 58 | 2 |
| 16 | `replay` | `internal/audit/siem/spool.go:135` | 74 | 0 |
| 16 | `StreamAuditLogs` | `server/grpc/services/audit_service.go:321` | 53 | 2 |
| 16 | `CopySecret` | `server/http/handlers/secrets_copy.go:21` | 53 | 2 |
| 16 | `main` | `examples/secret_crud/main.go:22` | 113 | 0 |

_55 functions total._
