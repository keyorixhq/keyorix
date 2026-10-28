- **INV-MW-project-mfa-gate-sentinel-only** The per-project MFA gate lets a
  `ProjectRequiresMFA` lookup error through ONLY when it is the definitive
  `storage.ErrProjectNotFound` (`storage.IsProjectNotFound`, never the error's text):
  `ProjectMFABlocked` returns true (deny) for every other error, and its gRPC twin
  `enforceProjectMFA` (server/grpc/services/conversions.go) returns `codes.Internal`.
  A missing project still passes so the endpoint's own 404/NotFound answers (#G17
  carve-out). Why: ERRLOSS-MFA-1 — both gates matched "not found" in the text, so any
  storage error so worded skipped MFA for an interactive session without a second
  factor. Guard: `project_mfa_sentinel_test.go` in this package
  (`TestProjectMFABlocked_LookalikeNotFoundErrorDenies`,
  `TestProjectMFABlocked_MissingProjectPassesToHandler404`) and in
  server/grpc/services (`TestEnforceProjectMFA_LookalikeNotFoundErrorDenies`,
  `TestEnforceProjectMFA_MissingProjectPassesToRPCNotFound`); internal/faultstorage on
  GetProject, en and ru, red before.
