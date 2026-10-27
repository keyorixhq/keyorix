- **INV-CORE-secret-acl-outage-is-error-not-no-grant** The per-secret ACL term of every
  secret authorization (`HasSecretACL` via `aclGrantsPermission`, used by
  `AuthorizeSecretAction` and `CheckSecretPermission`) reads only
  `storage.ErrSecretACLNotFound` (wrapped by `GetSecretACL` for `gorm.ErrRecordNotFound`
  only) as "no grant". Any other `GetSecretACL` error propagates, so the decision is a
  deny WITH an error, never a silent "no grant", and never an allow. The outcome does not
  depend on the server locale: no step classifies the error by its text. The same rule
  holds for the last-admin guard's `filterActiveHolders` (`storage.IsUserNotFound` only)
  and `GrantSecretACL`'s target lookup (`storage.IsSecretNotFound` only, which
  `GetSecret` wraps for leaf and folder nodes alike). Why: ERRLOSS-ACL-1 (2026-10-27
  silent-error-loss audit, findings 2 and 7). Guard: `secret_acl_outage_test.go`
  (`TestSecretACLOutage_FaultInjectedDeniesWithError`,
  `TestSecretACLOutage_RealStoreFailureDeniesWithError`, both under en and ru),
  `filter_active_holders_sentinel_test.go`, `require_secret_or_folder_node_test.go`,
  `internal/storage/store` `secret_acl_not_found_sentinel_test.go`,
  `get_secret_not_found_sentinel_test.go`. **Not covered**: the transports still answer
  any authorization error as a denial (HTTP `finishScopedPermissionRequest` -> 403, gRPC
  `authorizeSecretScoped` -> PermissionDenied), and several in-core list/bulk filters
  (`canReadSecret`, bulk extend/resume/rename) skip on any error; both fail closed but do
  not report the outage.
