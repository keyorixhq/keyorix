- **INV-GRPCSVC-group-user-role-mutations-require-read-gate** `GroupGRPCService`'s
  `CreateGroup`/`UpdateGroup`/`DeleteGroup`/`RestoreGroup`/`RemoveGroupMember`/
  `AddGroupMember`, `UserGRPCService`'s
  `CreateUser`/`UpdateUser`/`ReissueOneTimePassword`/`DeleteUser`, and
  `RoleGRPCService`'s `CreateRole`/`UpdateRole`/`DeleteRole` each gate through
  `authorizeGlobalMutation(ctx, cs, actor, <read-perm>, <write-perm>)`
  (`conversions.go`), never `authorizeGlobal(ctx, cs, actor, <write-perm>)` alone —
  the write permission by itself is not sufficient, even though it was before this
  fix. This mirrors HTTP's `/groups`, `/users` and `/roles` route groups, each gated
  by an outer `r.Use(RequirePermission(<read>))` on the whole group plus a per-route
  `RequirePermission(<write>)` on the mutating ones (`server/http/router.go`): a
  principal holding only the write/delete/assign permission — never granted the
  group's own read permission — could mutate groups/users/roles over gRPC in cases
  REST would deny. `GroupGRPCService.AddGroupMember` was initially left out of this
  invariant on the premise that the authzdiff harness's generated-permission sweep
  (known-01) didn't flag it and that it was already covered separately by
  INV-GRPCSVC-04's machine-ceiling check — review on this PR pointed out that
  carve-out was itself the exact asymmetry known-01 is about (INV-GRPCSVC-04 covers
  a different thing: the machine-granter ceiling, not the outer users.read gate), so
  it is now covered like every other RPC above. Why: authzdiff cross-layer
  differential harness waiver known-01 (PR #3981, a test-only harness not yet
  merged to main as of this fix; historical name D1).
  Guard: `authzdiff_known01_read_gate_family_test.go:TestGRPCMutations_RequireReadGate_Family`
  (one subtest per RPC above, all 13: the write/delete/assign permission alone is
  PermissionDenied, the same plus the read permission succeeds, so reverting any one
  call to `authorizeGlobal(<write>)` turns its subtest red) and
  `TestGRPCMutations_ReadGateFamily_CoversEveryGatedRPC` (AST scan: the methods
  calling `authorizeGlobalMutation` must be exactly the table's 13 RPCs). Not
  guarded: a new mutating RPC that never calls `authorizeGlobalMutation` at all.
