### Security

- `keyorix-migrate` no longer crashes when an Azure Key Vault list response carries a secret ID with no name (an empty string, a bare host, an unparsable URL): the entry is skipped like an entry with an empty name. The panic came from the Azure SDK's `ID.Name()`, which dereferences a nil pointer for those IDs, and the ID is server-controlled.

### Testing

- **Add hostile-server fuzz targets for migrate azuresource, gcpsource, and accessplan.** `FuzzAzureSourceHostileEndpoint` drives the real `azsecrets.Client` against a TLS httptest server (VALUE-LEAK, LIVENESS, SSRF, NO-PANIC/HANG/BOUNDED-WORK oracles); `FuzzGCPSourceHostileList` drives the `gcpAPI` interface seam (GCP uses gRPC, no httptest override) with fuzz-decoded scenario structs (VALUE-LEAK, LIVENESS, NO-PANIC/HANG oracles); `FuzzAccessPlanBuild` checks `Build` for non-determinism (DETERMINISM oracle). All three targets are registered in `scripts/fuzzing/targets.d/`.
