- **INV-CORE-mutation-refuses-inactive-actor** A mutating core entry point that takes the acting
  user's ID refuses a human actor whose account is not active (suspended, deprovisioned,
  `IsActive` false, unrecognized state: `userStillActiveForGrant`'s rule) before it acts, through
  the one helper `requireActorActive` (typed `ErrPermissionDenied`; a failed account read fails
  closed, untyped). Machine actors (ctx-tagged, an `actorIsMachine`/`actorKind` flag, or
  UserID 0) and the actorID-0 system pseudo-actor are not checked: they have no user account. A
  consequence: invitation acceptance re-checks the inviter's authority through `AssignUserRole`
  /`InviteMember`, so a suspended inviter's pending invitation no longer grants. Why: #4159
  (authzdiff known-02: core granted roles, members, invitations, approvals, machine tokens and
  secret mutations to a suspended actor the transports refuse at authentication). Guard:
  `server/authzdiff/core_suspended_actor_test.go` (`TestCoreRefusesSuspendedActor`, every bound
  core-enforced op as the suspended principal, red before #4159) and the strict authzdiff sweep.
  The per-secret read entry point `GetSecretForRead` (and `GetSecretForValueRead`, which delegates)
  makes the same refusal (#4336, Andrei's option 2): it calls `requireActorActive` first, except
  when the request's transport gate already allowed this read (`gateAllowedRead`, the
  OPT-READPATH-2 memo: that request was authenticated by the transport), so the hot read path
  pays no extra statement. Guard: `TestGetSecretForRead_RefusesInactiveActor`.
  **Not covered**: the waiver known-02 still names `secret.value.byid`/`byref` (read-path ops,
  kept narrow, not widened), and entry points the harness does not bind (a new mutating entry
  point must call `requireActorActive` itself; no static guard enforces that).
