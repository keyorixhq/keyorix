- **INV-STORE-users-unique-violation-is-typed** `LocalStorage.CreateUser` and
  `CreateUserWithRoleGrants` return an error matching `storage.ErrDuplicateUsername` when the
  insert collides with the partial users username index (`uniq_users_username_folded_active`;
  SQLite names the column `users.username_folded`) and `storage.ErrDuplicateEmail` for the
  email index, never one for the other. Core's username/email pre-checks are check-then-act
  reads, so the loser of a concurrent create reaches the index; core turns either sentinel into
  `core.ErrUserAlreadyExists` (gRPC AlreadyExists, REST 409) instead of a storage failure
  carrying the raw constraint text (gRPC Internal, REST 500). Why: REVFIX-3790-1 leftover,
  AUTHZ-ORACLE-1 item 4. Guard: `internal/core` `TestLocalStorage_UserUniqueViolationsAreTyped`
  and `TestCreateUser_UsernameRaceLoserGetsAlreadyExists` (production migration path, SQLite
  and Postgres), `server/grpc/services` `TestCreateUser_UsernameRaceLoserAnswersAlreadyExists`,
  `server/http/handlers` `TestCreateUser_UsernameRaceLoserAnswers409`.
  **Not covered**: `UpdateUser` / `UpdateUserIfActiveStateMatches` (a concurrent rename) still
  map only the email index; a username collision there is a storage failure.
