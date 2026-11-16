### Testing
- **authzdiff models environment-scoped role grants.** The cross-layer
  authorization differential's reference model now expresses role-grant
  environment scope independently of core: it reads `environment_id` from the
  user/group/machine grant tables and applies the `environment_id = 0 OR
  (environment_id = target AND the environment is live)` predicate, so a grant
  scoped to one environment is modelled as refused in every other environment.
  A new `secret.read.env` binding drives a secret value-read in two environments
  of the same project, and a planted-defect self-test (`env-scope-clause-removed`)
  removes the real environment clause from `userPrincipalPermissionSQL` and
  confirms the model catches the resulting cross-environment over-allow on core,
  REST and gRPC. Guarded by `TestV5bEnvScopedStrictSweep` and
  `TestV5bEnvScope_GrantInOneEnvRefusesTheOther` (default `go test`).
