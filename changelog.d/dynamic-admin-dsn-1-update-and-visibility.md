### Added
- **Replace a dynamic-secret config's admin DSN in place.** `PATCH /api/v1/dynamic-secrets/configs/{id}/admin-dsn`
  and gRPC `DynamicSecretService.UpdateConfigAdminDSN` replace the stored `admin_dsn` without deleting and
  recreating the config, e.g. to remove an option refused since #3952 (a private-CA `sslrootcert` or
  `tlsCAFile`). The same checks as create apply: dynamic-secret admin authority on the config's scope (403 /
  PermissionDenied), the private-network egress policy and the refused driver options (400 /
  InvalidArgument). The DSN is encrypted at rest, never returned, logged or written to the audit log; the
  change commits together with its `dynamic_secret.config_admin_dsn_updated` audit row (503
  `audit_unavailable` when the audit log refuses it, nothing changed).

### Fixed
- **gRPC dynamic-secret refusals of the caller's own `admin_dsn`.** A refused driver option or a
  private-network target on `CreateConfig` answered `Unavailable` ("backend operation failed"); it is
  `InvalidArgument` with the same text REST sends with its 400. An audit-log refusal is `Unavailable` with the
  `audit_unavailable` reason.
