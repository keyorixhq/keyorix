- **INV-AUTHZDIFF-environment-scoped-grant-modelled** The reference model
  (`model_test.go`) expresses role-grant **environment scope** independently of
  core: it reads `environment_id` from all three grant tables (`user_roles`,
  `group_roles`, `machine_identity_roles`) directly and applies the predicate
  `grant.environment_id = 0 OR (grant.environment_id = target.environment AND
  that environment is live)` — the all-environments wildcard at 0, a specific
  environment otherwise, a soft-deleted environment voiding the grant. A
  `requirement` names the environment its permissions are checked at
  (`requirement.env`); a secret operation checks at the secret's own environment
  (core builds `Scope{secret.ProjectID, secret.EnvironmentID}` in
  `AuthorizeSecretAction`). This mirrors, without calling, the predicate core
  resolves authorization through — `userPrincipalPermissionSQL` /
  `machinePrincipalPermissionSQL` in
  `internal/storage/store/local_principal_permission.go` (reached by
  `core.Authorize` → `ResolveUserPermissionAt`/`ResolveMachinePermissionAt`), the
  same shape `INV-CORE-15`/#2857 made load-bearing (a `{project, env X}` grant
  must not satisfy a check in a different environment, nor count at global scope).
  Why: environment scope was the one grant dimension the harness did not model
  (`model_test.go`'s former header line "Environment-scoped grants are not
  modelled: the harness never creates one"), so a regression that let an
  environment-scoped grant leak across environments was invisible to the
  differential.
  Guard: `TestV5bEnvScopedStrictSweep` and `TestV5bEnvScope_GrantInOneEnvRefusesTheOther`
  (`sweep_v5b_test.go`, default `go test`, skipped under `-short`) drive the
  `secret.read.env` binding with the custom role granted `secrets.read` in ONE
  environment and read a secret in that environment (allowed) and in the OTHER
  environment of the same project (refused) — on the model and on every transport
  leg — and fail on any uncalibrated or `unexplained` case; the plant
  `env-scope-clause-removed` (`plants_test.go`) removes the real environment
  clause from `userPrincipalPermissionSQL` and the restricted sweep then records
  core+REST+gRPC all over-allowing the cross-environment read the model denies
  (bucket `unexplained`), with a clean sweep recording none. Red/green verified
  2026-11-15 by applying the plant to the production file (4 `unexplained` cases
  appeared across both projects/environments, and the direct env-scope pin went
  red) and reverting.
  Does NOT verify: per-secret ACL/share elevation across environments (the bound
  secrets carry none); write/delete/list/export as distinct routes (the
  authorization scope is the same `{project, environment}` — the model rule is
  route-independent and only the read route is bound as the representative);
  environment-scoped grants held via the group or machine route beyond what the
  sweep/fuzzer sample.
