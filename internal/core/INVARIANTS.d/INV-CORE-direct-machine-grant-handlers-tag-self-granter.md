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
  (authzdiff cross-layer differential harness waiver known-06, historical name D6) — the harness's
  own cross-layer comparison flagged it because core's `AddProjectMember`/`SetProjectMemberRole`
  apply no such actor-kind-specific restriction themselves; only these two HTTP handlers'
  omission of the tag did. The same shape was fixed earlier, independently, at
  `AddGroupMember` (`server/http/handlers/groups_members.go:91`). Current known-complete call-site
  inventory tagging correctly: `groups_members.go:91`, `project_members.go:186` and `:247`,
  `rbac.go:498`/`707`/`830`, `machine_identities.go:600`, `project_memberships.go:165`,
  `users_crud.go:181`, and the gRPC equivalents `group_service.go:177`, `role_service.go:243`,
  `user_service.go:126` — derived by `grep -rn "WithSelfMachineGranter(ctx" --include=*.go` and
  reasoning about each call site's handler, not generated.
  Guard: targeted regression tests per fixed call site, not a repo-wide scan —
  `groups_members_machine_ceiling_test.go`'s `TestAddGroupMember_MachineActor*` pair and this
  fix's `server/http/handlers/project_members_machine_ceiling_test.go`'s four
  `TestAddProjectMember_MachineActor*`/`TestUpdateProjectMember_MachineActor*` tests: each proves
  a machine actor lacking sufficient permission is refused and a machine actor holding sufficient
  permission is allowed. UNGUARDED as a class: no registry/AST-derived test enumerates every HTTP
  handler or gRPC method that reaches `requireGranterHoldsRolePermissions` with a machine-capable
  actor and asserts the tag is present (the existing `TestEveryDirectRoleGrantChecksAuthority`,
  `server/http/role_grant_authority_guard_test.go`, guards a different shape — a handler bypassing
  the ceiling call entirely via a direct `.Storage().Create*/Update*`, not a handler that calls the
  ceiling but omits this tag) — a new direct-grant handler added for a machine-capable route
  without the tag would silently fail closed rather than being caught by CI.
