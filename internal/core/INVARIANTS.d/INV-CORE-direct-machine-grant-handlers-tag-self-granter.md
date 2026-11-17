- **INV-CORE-direct-machine-grant-handlers-tag-self-granter** Any DIRECT (non-`/system`-proxy)
  HTTP handler or gRPC service method that authenticates a machine actor and then calls into a
  `KeyorixCore` method reaching `requireGranterHoldsRolePermissions`/
  `requireGranterHoldsRolePermissionsNoBaseline` (the escalation-by-proxy ceiling on any role
  GRANT) must first tag `ctx` with `core.WithSelfMachineGranter(ctx, actor.PrincipalID())` when
  `actor.ActorKind() == core.ActorTypeMachine`. Without the tag,
  `checkGranterHoldsPermission`'s `case actorIsMachine:` branch treats the call exactly like an
  untagged `/system` proxy relay and returns `(false, nil)` unconditionally — fail-closed, not
  fail-open, but still a real correctness defect: a machine actor that genuinely holds every
  permission the target role bundles, including `roles.assign` at the scope, can never grant
  that role AS ITSELF through that entry point, no matter its actual authority. Found missing at
  `server/http/handlers/project_members.go`'s `AddProjectMember`/`UpdateProjectMember`
  (authzdiff cross-layer differential harness waiver known-06, historical name D6) and, when the
  guard below was first written, at `users_roles.go`'s `UpdateUserRoles`. The same shape was
  fixed earlier, independently, at `AddGroupMember`
  (`server/http/handlers/groups_members.go`). A core function that tags for itself
  (`WithSelfMachineGranter` inside `internal/core`, as invitations and membership lifecycle do)
  needs no handler-side tag.
  Guard: `TestEveryDirectMachineGrantEntryTagsSelfGranter`
  (`server/http/machine_self_granter_tag_guard_test.go`). It derives the set of core functions
  reaching the ceiling from the `internal/core` call graph, takes every router-registered HTTP
  handler and every exported `server/grpc/services` method that reaches one, and requires a
  `WithSelfMachineGranter` call (directly or through a same-package helper such as
  `creationGrantCtx`) before the first such call, plus that every tag call sits under an `if`
  on the machine actor kind. The call forms it recognises, and the ones it is blind to (method
  values passed without a call, flow-insensitive ordering), are stated in the file's doc comment;
  `TestMachineSelfGranterGuardDetectsOmittedTag` proves it goes red on a handler that omits the
  tag, tags after the call, or tags outside the machine branch. The per-site tests
  (`groups_members_machine_ceiling_test.go`, `project_members_machine_ceiling_test.go`,
  `users_roles_machine_ceiling_test.go`) prove the allow and refuse behaviour end to end.
  Report-only until its `docs/guard-rollout.d/` row is deleted.
