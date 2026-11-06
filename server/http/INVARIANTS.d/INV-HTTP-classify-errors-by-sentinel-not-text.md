- **INV-HTTP-classify-errors-by-sentinel-not-text** A handler (and a gRPC service) maps a core or
  storage error to a status with `errors.Is` on a sentinel (`storage.ErrUserNotFound`,
  `storage.ErrGroupNotFound`, `storage.ErrSecretNotFound`, the per-entity sentinels in
  `internal/core/storage/errors_notfound.go`, `core.ErrPermissionDenied`, ...), never with
  `strings.Contains(err.Error(), ...)`: the text is translated (de/es/fr/ru) and carries a
  prefix core adds to any storage error, so a text match both turns a real 404/403 into a 500
  under a non-English locale and turns an unrelated failure that happens to contain the word
  ("permission denied" from the OS, a driver error under a "user not found" prefix) into a
  404/403. Migration state: done for the user routes (`users_crud.go`, `users_roles.go`,
  `admin_impersonation.go`); `machine_identities.go`'s `IssueMachineToken` now also checks
  `errors.Is(err, core.ErrPermissionDenied)` before its substring switch (authzdiff known-03/D3
  follow-up: `ErrMachinePrivilegeCeilingDenied`'s wrapped prose never matched any of that switch's
  fixed substrings, so every legitimate MACH-001 ceiling refusal fell through to the default 500);
  the other families move over one pull request each (ERRLOSS-SENTINELS-1 task 3). A text match that is not about a translated message (driver SQL dialect, an English
  literal core returns without a sentinel) stays until its sentinel exists. Guard: per family a
  table test over the real handler that runs under `en` and a translated pseudo-locale
  (`error_class_locale_helper_test.go`) and asserts not-found -> 404 and an injected storage
  failure (`faultstorage`) -> 5xx: `users_error_class_locale_test.go`
  (`TestUserRoutes_MissingUserIs404InEveryLocale`, `TestUserRoutes_StorageFaultIs5xxInEveryLocale`,
  `TestImpersonationStart_TargetLookupClassifiedByFailureInEveryLocale`). UNGUARDED until the
  repo-wide text-match guard lands (task 4): a new text match in an unmigrated handler is not
  caught by CI.
