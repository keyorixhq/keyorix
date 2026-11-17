- **INV-CORE-refusals-typed-machine-and-membership** A core refusal on the human-only operations
  (secret share/ACL grant/tags/description/move/copy/certificate, extend-expiring, access request,
  share update, break-glass) and on membership transition is typed: it matches
  `ErrPermissionDenied`. A machine actor (UserID 0, machine type on ctx) is refused by
  `refuseMachineActor` before the operation's "actor ID is required" validation;
  `ErrMembershipAuthorityRequired` and `ErrRestrictedPATCannotBreakGlass` are permission sentinels;
  `CopySecret`'s refused source answer is not-found AND a refusal, identical for a missing and a
  forbidden source (no existence oracle, #G14). REST answers these 401/403, gRPC
  PermissionDenied/Unauthenticated, never 400/500 or InvalidArgument/Internal. Why: #4162, #4163
  (authzdiff known-08, known-09). Guard: `server/authzdiff/core_typed_refusal_test.go`
  (`TestCoreRefusalsAreTyped`, red before #4162/#4163) and the strict authzdiff sweep, which no
  longer waives any untyped core error. **Not covered**: whether a machine should be allowed any
  of these operations (unchanged: still refused; a product decision).
