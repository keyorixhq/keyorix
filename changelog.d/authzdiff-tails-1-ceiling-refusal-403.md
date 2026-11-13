### Fixed

- `POST /api/v1/user-roles`, `POST /api/v1/projects/{id}/invitations`, `PUT /api/v1/projects/{id}/access-requests/{requestId}` (approve) and `POST /api/v1/projects/{projectId}/environments/{id}/restore` now answer 403 when the caller passes the route's permission check but core refuses the request: the caller does not hold every permission of the role it grants, or, for the restore, lacks the authority to reinstate the project's administrative role assignments. They answered 500 before. Nothing was written in either case.
