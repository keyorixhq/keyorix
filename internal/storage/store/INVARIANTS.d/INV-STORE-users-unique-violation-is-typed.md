- **INV-STORE-users-unique-violation-is-typed** `LocalStorage.CreateUser`,
  `CreateUserWithRoleGrants`, `UpdateUser` and `UpdateUserIfActiveStateMatches` return an error
  matching `storage.ErrDuplicateUsername` when the write collides with the partial users username
  index (`uniq_users_username_folded_active`; SQLite names the column `users.username_folded`) and
  `storage.ErrDuplicateEmail` for the email index, never one for the other. Core's username/email
  pre-checks are check-then-act reads, so the loser of a concurrent create or rename reaches the
  index; core turns either sentinel into `core.ErrUserAlreadyExists` (gRPC AlreadyExists, REST 409;
  SCIM provision: `ErrSCIMUserExists`, 409 uniqueness) instead of a storage failure carrying the
  raw constraint text (gRPC Internal, REST 500). The update paths are single statements that
  return the non-nil error, so an enclosing transaction rolls back; a violation is never caught
  and swallowed inside a transaction (PostgreSQL aborts it). Why: REVFIX-3790-1 leftover,
  AUTHZ-ORACLE-1 item 4, AUTHZ-ORACLE-TAILS-1 item 1. Guard: `internal/core`
  `TestLocalStorage_UserUniqueViolationsAreTyped`, `TestLocalStorage_UserUpdateUniqueViolationsAreTyped`
  and `TestLocalStorage_UsernameRenameRace_TwoWriters` (two real concurrent writers),
  `TestCreateUser_UsernameRaceLoserGetsAlreadyExists` (production migration path, SQLite and
  Postgres), `server/grpc/services` `TestCreateUser_UsernameRaceLoserAnswersAlreadyExists`,
  `server/http/handlers` `TestCreateUser_UsernameRaceLoserAnswers409`.
  **Not covered**: these tests drive `LocalStorage` and core; whether a `storage.type: remote`
  client sees the sentinel across the proxy is not asserted.
