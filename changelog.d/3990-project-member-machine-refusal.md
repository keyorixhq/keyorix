### Fixed

- `POST /api/v1/projects/{id}/members` and `PUT /api/v1/projects/{id}/members/{userId}` now refuse a machine-identity caller with 403 before any role or user is looked up. `POST` used to answer such a caller (and any caller failing the privilege ceiling) with 500. The invitation and membership-lifecycle paths are unchanged. (#3990)
