### Security
- **A secret access approval no longer survives a concurrent delete.** Approving a restricted-read access request while the secret (or its project) was being deleted could commit the approval after the delete had closed the secret's approved requests, so restoring the secret from the recycle bin brought the approval back with no re-review. The approval now re-checks the secret under a row lock in its own transaction and is refused with "cannot approve: secret N no longer exists" when the delete won. Guarded by two-pool Postgres and SQLite race tests in `internal/core`.

### Testing
- **Membership and grant routes must pass the request's machine actor to core.** A new guard in `internal/core/guards` fails when a REST handler calls a core method that takes `actorIsMachine` (or a machine identity ID) with anything other than the request's own actor kind.

### Documentation
- **`POST /api/v1/projects/{id}/members` documents its 403**, including the privilege ceiling that also applies to machine-identity tokens.
