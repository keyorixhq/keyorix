### Security
- **Setting a member's roles is judged on every requested role.** `PUT /api/v1/projects/{id}/members/{userId}` and `PUT /api/v1/users/{id}/roles` used to check the granter ceiling only on roles the request added, so a caller who may not grant a role got 200 when the target already held it and 403 otherwise, which revealed the target's roles. Now a caller who may not grant a requested role gets 403 whatever the target holds, including for a request that changes nothing or only removes other roles. See `docs/UPGRADING.md`.

### Fixed
- **`POST /api/v1/projects/{id}/memberships` answers 403 for a role the caller may not grant.** It answered 500. The response is documented in the OpenAPI document, as it now is for `POST /api/v1/projects/{id}/members`.
