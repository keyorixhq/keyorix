### Fixed
- **Ordinary refusals on the catalog, role and secret routes no longer answer HTTP 500.** Deleting a project that still has secrets (409, `core.ErrProjectHasSecrets`), a duplicate project or environment name (409), restoring something that is not deleted, or restoring under a deleted project or environment (404 / 409), assigning a role that does not exist (404) and sharing a secret with yourself (400) now answer their own status through the shared error classifier. Response bodies keep their wording; the driver text of a duplicate-name constraint no longer reaches a client.
- **A storage read fault on secret read, create and copy answers 503 with `Retry-After`** instead of a generic 500 (`GET /secrets/{id}`, `GET /secrets/value`, `POST /secrets`, `POST /secrets/{id}/copy`); `GET /secrets/value` declares the 503.

### Internal
- The stateful OpenAPI fuzzer no longer waives `OPENAPI-STATEFUL-3` for `deleteProject`, `updateProject`, `createProjectEnvironment`, `restoreEnvironment`, `restoreSecret`, `renderSecretTemplate` and `shareSecret`; each is pinned by a handler table test.
