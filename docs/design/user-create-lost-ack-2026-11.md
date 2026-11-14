# User-create paths and the lost acknowledgement (2026-11, #3225)

A create transaction can commit and still return an error: the COMMIT reached the
database but its acknowledgement did not reach the server (`KindEffectThenError` in
`internal/faultstorage`). A path that reads that error as "nothing committed"
answers failure for an account that exists, skips what it does after the commit
(post-commit audit rows, the password-history seed, the session), and a retry meets
a duplicate. #4208 fixed `createUser` with a read-back helper,
`KeyorixCore.userCreateLanded` (`internal/core/users.go`). This page lists every
core path that creates a user, how it behaves today, and which change covers it.

## How the list was derived

Not by hand. Three sources, each a superset check on the others:

1. `rg 'CreateUser\(' internal/core --glob '!*_test.go'`: the storage insert sites
   (`tx.CreateUser`) and the core wrappers (`c.CreateUser`).
2. The storage interface methods that insert a user: every method whose name starts
   with `CreateUser` in `internal/core/storage/iface_user.go` (today `CreateUser` and
   `CreateUserWithRoleGrants`; `rg 'CreateUserWithRoleGrants\(' internal/core` finds
   the one caller the first query misses).
3. The fault-injection op catalog (`server/faultops`, `opCatalog` and the
   `registerOps` files): every op whose fault-free run adds a `User` row was driven with
   `WithTransaction` commit-then-error at call ordinals 1..6, which also shows which
   ordinal is the create.

The guard (`TestPartialCommit_EveryUserCreateSiteHandlesLostAck`,
`server/faultops/partial_commit_user_create_test.go`) recomputes source 2 and the
call sites of source 1 from the code on every run. A new insert site with no row in
`userCreateLostAckSites` fails it.

## The paths

| Path (core function) | Reached from | Today's behaviour on a lost ack | Verdict |
|---|---|---|---|
| `createUser` (`users.go`) | `CreateUser`, `CreateUserAudited`, REST `POST /api/v1/users/` (no role/assignments), `CreateUserWithSetupLink`, `CreateUserWithOneTimePassword` (REST and gRPC) | read back; a landed row is answered as success and the password history is seeded | already correct (#4208) |
| invitation accept, project and global (`completeInvitationAccept`, `setup_consume.go`) | `POST /auth/setup/consume`, purpose `invitation_accept` | goes through `c.CreateUser`, so the #4208 read-back applies; the accept then continues (`LogUserCreated`, token consume, grants) | already correct (#4208). Both invitation kinds use the same function; the global one only differs in `applyInvitationGrants` |
| `CreateUserWithAssignments` (`users.go`) | gRPC `UserService.CreateUser` (admin-set password), REST `POST /api/v1/users/` with `role` or `project_assignments` | answered `Internal`/500 while the user, its role grants and `user.created` committed; password history not seeded; a retry gets "already exists" (oracle (d) flags it) | **fixed by this PR** |
| `ProvisionSCIMUser` (`scim.go`) | SCIM `POST /scim/v2/Users` | answered 500 while the user, its baseline role and `scim.user_provisioned` committed; the IdP's retry gets 409 uniqueness and never learns the id. No oracle flagged it (the state equals the fault-free one) | **fixed by this PR**: a landed row answers 201 with the user; an unreadable outcome answers 503 + `Retry-After` with the SCIM error body |
| `provisionSSOUser` (`sso.go`) | OIDC `CompleteSSO` (`ensureSSOUser`) and SAML `CompleteSAML` JIT | login refused while the account and its default role committed; the post-commit `auth.sso_jit_provisioned` row was never written, and the next login resolves the account by its `sso:` external id as an existing one, so that row never appears. No oracle flagged it | **fixed by this PR**: a landed row writes `auth.sso_jit_provisioned` and the login continues |
| `bootstrapSystemLocked` (`auth_bootstrap.go`) | `POST /system/init` (`handlers.AuthHandler.InitSystem`) | answered failure while the admin, the catalog and the initialised marker committed; the post-commit `user.created` / `project.created` rows and the password-history seed are skipped; the bootstrap token stays in memory (harmless: the marker refuses a second bootstrap, and a retry answers `AlreadyInitialized`) | **out of scope**: verify only here, `auth_bootstrap.go` is being changed by DEMO-COPY-TAILS (#4218). Left as a LEFTOVER for after #4218 merges |

## What "fixed" means on each path

- The answer reflects the commit: the read-back finds the row the transaction
  inserted (matched on id and username), and the path continues down its success
  path. A real rollback (the row is not there) still answers the error, and leaves
  no user (`…RolledBackStaysAnError` tests).
- A read-back that itself fails cannot tell. The error stands (fail closed) and
  carries `core.ErrUserCreateOutcomeUnknown`; SCIM answers that 503 + `Retry-After`,
  the other transports keep their storage-error answer. If the row did land, a retry
  finds it (409 uniqueness on SCIM, "already exists" elsewhere): the outcome is never
  a second account.
- An SSO account is never half-provisioned: the user row and its default role commit
  in one transaction, so either both exist or neither does. What the lost ack used
  to lose was the `auth.sso_jit_provisioned` audit row and the login itself.

## Not covered

- `bootstrapSystemLocked`, see the table.
- The off-box audit forward. A create through `withAuditedMutation`
  (`CreateUserAudited`, `CreateUserWithAssignments`, `ProvisionSCIMUser`) forwards
  its committed audit rows (`auditForwardSink.Flush`) only after a clean commit, so on
  a delivered lost ack the row is in the database but was not forwarded. This is the
  same for every audited mutation, not only creates, and belongs to the audit flusher.

## knownOpenTolerances

None of these ops had a `knownOpenTolerances` (or other exemption) row for the
lost-ack case, so there is nothing to remove. Two of the three bugs (SCIM, SSO JIT)
were invisible to the generic oracles because the committed state equals the
fault-free state; the guard asserts the answer directly instead.
