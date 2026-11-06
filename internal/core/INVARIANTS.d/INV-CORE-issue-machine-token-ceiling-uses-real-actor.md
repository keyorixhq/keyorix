- **INV-CORE-issue-machine-token-ceiling-uses-real-actor** `IssueMachineToken`'s
  MACH-001 privilege-ceiling check (`requireMachinePrivilegeCeiling`) must be called
  with the REAL authorizing principal — `actorKind`/`actorPrincipalID`, threaded
  through from the caller's `actor.ActorKind()`/`actor.PrincipalID()` — never a
  hardcoded `ActorTypeUser` paired with `actorID` (`actorID` is audit attribution
  only, and is always 0 for a machine caller per ADR-030). `requireMachinePrivilegeCeiling`
  itself is already actor-kind-aware (it branches on `actorType == ActorTypeMachine`
  for the admin-tier-target case, and resolves the actor's own authority via
  `AuthorizePrincipal(ctx, actorType, principalID, permRolesAssign, scope)` either
  way) — the bug was entirely in what `IssueMachineToken` passed it. Both the HTTP
  route (`RequireScopedPermission(roles.assign)`) and the gRPC RPC gate
  (`authorizeScoped(..., permRolesAssign, ...)`) in front of this call already admit
  a machine actor holding `roles.assign`; without this invariant, a machine actor the
  route gate had just admitted was then refused by this inner check unconditionally,
  regardless of its real authority — fails closed (no escalation), but contradicts
  the route gate it sits behind. Why: authzdiff cross-layer differential harness
  waiver known-03 (`server/authzdiff/REPORT.md`, historical name D3).
  Guard: `machine_token_ceiling_actor_kind_test.go`
  (`TestIssueMachineToken_CeilingUsesRealActorKind`),
  `server/http/machine_token_ceiling_actor_kind_test.go`
  (`TestIssueMachineTokenHTTP_MachineActorHoldingRolesAssign_Succeeds`,
  `TestIssueMachineTokenHTTP_AdminTierTarget_MachineActorStillDenied`).
  **Not covered**: a future second call site of `requireMachinePrivilegeCeiling`
  reintroducing the same hardcoded-actor-kind mistake independently — this invariant
  only watches `IssueMachineToken`'s own call.
