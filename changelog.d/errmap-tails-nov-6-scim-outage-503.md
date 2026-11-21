### Fixed
- **SCIM provisioning answers 503 with Retry-After during an audit or storage outage.** A SCIM create, replace or patch of a user or group whose audit row the audit log refused, or whose storage read failed, answered 500 with the generic detail. It now answers 503 with an RFC 7644 error body, a fixed detail and `Retry-After`, like every other REST handler (`audit_unavailable`, `storage_unavailable`), so an IdP retries instead of treating the provisioning as broken. `GET /scim/v2/Groups/{id}` answers the same 503 for a storage read fault.

### Documentation
- **OpenAPI declares the 404 and 503 answers of four operations.** `assignUserRole` (404 absent target user, 503), `classifySecret`, `getSecretByName` and `setSecretAutoRotate` (503 for a storage read fault). The web, CLI and migrate generated clients are regenerated.
