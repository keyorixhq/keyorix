### Added
- **`keyorix dynamic-secret set-admin-dsn <config-id>` and `keyorix dynamic-secret refused-dsn --project-id N`.** The first replaces a stored admin DSN in place (the #4193 route), for example to drop a private-CA `sslrootcert` or `tlsCAFile` that has been refused since #3952; the second lists the project's configs whose stored DSN names such an option, with option names only (`-o json|yaml` supported). The new DSN is read from `KEYORIX_DYNAMIC_ADMIN_DSN`, a hidden prompt or stdin and is never accepted as a flag (`--admin-dsn` is refused even with `KEYORIX_ALLOW_INSECURE_SECRET_FLAGS=1`); neither command prints it, and an error from the server is scrubbed of it.

### Documentation
- The `dynamic_secrets` section of `CONFIGURATION.md` and the upgrade note no longer say a stored `admin_dsn` cannot be edited; they name the two commands and the rule that the DSN never goes on the command line.

### Testing
- The `admin_dsn` replace route (REST and gRPC) is now an `opCatalog` operation and `StatusFuzzed` in the faultops inventory.
