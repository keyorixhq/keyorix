- **INV-CORE-machine-token-issue-cannot-widen-caller** A machine identity acting as itself
  (`WithSelfMachineGranter`, not a /system relay) cannot use `IssueMachineToken` to gain a
  permission it does not already hold, or to shed its credential's CIDR or federation
  confinement. It cannot issue a token for itself. Its presented credential
  (`WithMachineCallerCredential`, set by the REST and gRPC handlers) must be a live opaque
  `kx_machine_` credential of that machine with no CIDR allowlist; a federated JWT or an
  unrecorded credential is refused. It is refused a target whose roles are admin-tier by the
  bypass flag, a canonical admin name or the permission bundle (`roleIsAdminTier`). For every
  other target it must hold `roles.assign` at the project and, at each scope where the target
  holds a role grant, every permission those roles bundle
  (`requireMachineActorHoldsTargetPermissions`, the rule `requireGranterHoldsRolePermissions`
  applies when a machine grants itself a role). All refusals wrap
  `ErrMachinePrivilegeCeilingDenied`; a lookup error is returned, never read as allow. Why:
  REVIEW-3993-DEEP-1, a CIDR-restricted machine minted itself an unrestricted, non-expiring
  token (the machine counterpart of PAT-GUARD-1); REVIEW-3993-DEEP-2, a roles.assign-only
  machine minted a token for a peer that reads and writes the project's secrets. Guard:
  `machine_token_caller_credential_test.go`, `machine_token_admin_tier_target_test.go`,
  `machine_token_target_permission_ceiling_test.go`, server/http/handlers
  `machine_token_caller_credential_test.go`, server/grpc/services
  `TestGRPCIssueMachineToken_MachineCaller`.
  **Not covered**: the calling credential's expiry, so an unrestricted credential that
  expires can still issue a non-expiring token for a peer the caller fully covers; permissions
  the target gains after the token is issued (a later grant is checked against its granter,
  not against whoever holds the target's tokens); a user caller authenticated by a CIDR-only restricted PAT;
  and the user path's non-admin branch, which requires only `roles.assign` and not that the
  actor holds what the target holds (INV-CORE-01 follow-up issue).
  **Mint-time ceiling only (by design, Andrei 2026-11-08, PAT-SCOPE-TAILS-1 item 4):** the
  privilege ceiling above is checked when the token is minted and never again. A machine
  credential records no issuer; its authority is the machine identity's own roles,
  re-resolved live at each use. If the user (or machine) that issued it later loses the
  authority to issue it, already-minted machine tokens stay valid until revoked or
  expired. This differs from a PAT, whose owner's lost ceiling is refused at use time
  (`server/http` `pat_owner_lost_ceiling_use_time_test.go`). Open idea, not a task:
  record `issuer_user_id` on the credential and re-check the issuer's ceiling at use time
  (a schema and read-path change, its own session); see the ADR-042 addendum of 2026-11-08.
