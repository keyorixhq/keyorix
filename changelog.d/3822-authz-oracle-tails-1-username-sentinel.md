### Fixed
- **A concurrent rename to a taken username answers AlreadyExists / 409.** `UpdateUser` and `UpdateUserIfActiveStateMatches` now map a collision on the users username index to `storage.ErrDuplicateUsername` (SQLite and PostgreSQL), as `CreateUser` does, and `core.UpdateUser` turns it, and the email twin, into `ErrUserAlreadyExists` (REST 409, gRPC `AlreadyExists`) instead of a storage failure (500 / `Internal`) carrying the constraint text. SCIM provisioning answers 409 `uniqueness`, SSO JIT provisioning and the first-admin bootstrap answer "already exists"; the loser leaves no user row, grant or audit event.
- **Session-revocation failure text names the personal access tokens.** When the PAT listing fails during an account-state change, the `SECURITY:` log line and the `auth.session_revocation_failed` audit row said "could not list the sessions of user N"; they now say "the personal access tokens".

### Internal
- Removed the unreachable "admin authority is required" / "administrator" 403 branch from the secret access-request resolve handler: core answers a caller without authority "access request not found" (404) before any of those texts can occur.
