- **INV-CORE-mfa-ops-refuse-inactive-actor** The three MFA mutation ops that take the acting
  user's ID — `ActivateMFA`, `DisableMFA`, `RegenerateMFARecoveryCodes` — refuse a suspended /
  inactive human actor via `requireActorActive` as their first act, before any TOTP /
  recovery-code / password evaluation or MFA storage read (a specialisation of
  [[INV-CORE-mutation-refuses-inactive-actor]]). The refusal is re-wrapped by
  `mfaActiveGuardRefusal`: a `requireActorActive` `ErrPermissionDenied` becomes the generic
  `reauthRejectedError{"invalid code or password"}` (still `errors.Is ErrPermissionDenied`, so a
  transport maps it 403, not 401), while a storage read fault (`ErrStorageReadUnavailable`, not
  `ErrPermissionDenied`) propagates unchanged for a 503. **Anti-enumeration**: a caller who knows
  only a username cannot distinguish "account suspended" from "wrong credential" by the error
  text — the suspended-actor refusal is byte-identical to the wrong-credential refusal. Why:
  the transports already refuse a suspended account at authentication (session/PAT token
  validation checks `IsActive && !AccountLoginBlocked`, so this is defense in depth for any
  future direct-core caller and for the test surface), but the three core methods themselves
  took the actor's roles at face value and, once the guard was added, a naive typed refusal
  would have leaked account state through the error text. Guard:
  `internal/core/actor_active_entrypoints_test.go`
  (`TestSuspendedActorRefusedAtEntryPoints`, the three MFA ops refused with `ErrPermissionDenied`
  before any storage call other than the account read) and
  `internal/core/reauth_grant_suspend_test.go`
  (`TestMFAOpsRefusalTextMatchesWrongPassword`, the suspended-actor refusal text is identical to
  the active-account wrong-credential text for all three ops). **Not verified here**: that a
  transport independently refuses a suspended actor at these routes (it does, at the
  `Authentication` middleware, verified separately) — this invariant is purely about the core
  methods' own behaviour and the anti-enumeration property of their refusal text.
