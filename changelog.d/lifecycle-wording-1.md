### Fixed

- Restoring a secret that is not deleted now answers 409 Conflict with "secret N is not deleted; nothing to restore" instead of a 404 "Storage operation failed: Secret not found" that read like a storage fault (#3737). A secret that does not exist still answers the same 404, and the route's permission check still runs first.

### Changed

- The break-glass list response carries an additive `username` per activation (omitted when the user cannot be read); the `break_glass.activated` and `break_glass.revoked` audit descriptions already name the user like `role.assigned` does (#3741). The OpenAPI description of the audit-search `actor` filter now matches its behaviour: user or machine-identity name, case-insensitive, partial.
