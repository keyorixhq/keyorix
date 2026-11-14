### Added
- **Replace a dynamic-secret config's admin DSN in place.** `PATCH /api/v1/dynamic-secrets/configs/{id}/admin-dsn`
  and gRPC `DynamicSecretService.UpdateConfigAdminDSN` replace the stored `admin_dsn` without deleting and
  recreating the config, e.g. to remove an option refused since #3952 (a private-CA `sslrootcert` or
  `tlsCAFile`). The same checks as create apply: dynamic-secret admin authority on the config's scope (403 /
  PermissionDenied), the private-network egress policy and the refused driver options (400 /
  InvalidArgument). While the config has an active or `revoke_failed` lease the new DSN must name the same
  host and port (for kubernetes the same `api_server`, `namespace` and `revocable`), because those leases
  are revoked through it (409 / FailedPrecondition). The DSN is encrypted at rest, never returned, logged or written to the audit log; the
  change commits together with its `dynamic_secret.config_admin_dsn_updated` audit row (503
  `audit_unavailable` when the audit log refuses it, nothing changed).
- **Find the dynamic-secret configs that need it.** `GET /api/v1/dynamic-secrets/configs/refused-admin-dsn?project_id=`
  and gRPC `DynamicSecretService.ListConfigsWithRefusedAdminDSN` list, read-only, a project's configs whose
  stored admin DSN names an option refused since #3952, with the refused option names and the live lease
  count (never the DSN or an option value). Needs dynamic-secret admin authority on the project; the startup
  warning still covers every project.

### Fixed
- **gRPC dynamic-secret refusals of the caller's own `admin_dsn`.** A refused driver option or a
  private-network target on `CreateConfig` answered `Unavailable` ("backend operation failed"); it is
  `InvalidArgument` with the same text REST sends with its 400. This applies to every dynamic-secret RPC,
  so issue, renew and revoke against a config whose stored DSN is refused answer `InvalidArgument` too. An audit-log refusal is `Unavailable` with the
  `audit_unavailable` reason.
