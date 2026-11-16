### Fixed
- **OpenAPI: `DELETE /api/v1/rejection-reason-templates/{id}` is documented as 204.** The handler answers 204 with no body (and 400 for a non-numeric id); the published spec declared only 200, so a client generated from it waited for a status the server never sends (#4244). The spec now declares 204 and 400.
- **OpenAPI: `deleteUser` and `restoreUser` declare their 400 refusals.** An invalid id, user id 0 and (for delete) the caller's own account were already answered 400 but were missing from the spec.
