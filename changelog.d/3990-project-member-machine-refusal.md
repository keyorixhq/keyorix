### Changed

- **Breaking for machine callers:** `PUT /api/v1/projects/{id}/members/{userId}` now refuses a machine-identity caller with 403 in every case. Before, a machine holding `roles.assign` at the project could use it on an existing member when nothing was being added: naming the role the member already held answered 200 (and wrote a `role_confirmed_unchanged` audit row), and naming one of several roles the member held removed the others and answered 200. `DELETE /api/v1/projects/{id}/members/{userId}` is unchanged. (#3990)

### Fixed

- `POST /api/v1/projects/{id}/members` now refuses a machine-identity caller with 403 before any role or user is looked up, and answers 403 for any permission refusal (a human failing the privilege ceiling included). It used to answer these with 500. A machine `PUT` that adds a role was already refused with 403 by the privilege ceiling and now gets the same up-front refusal. The invitation and membership-lifecycle paths are unchanged. (#3990)
