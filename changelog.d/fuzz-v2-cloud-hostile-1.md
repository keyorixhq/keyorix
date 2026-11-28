### Security

- `keyorix-migrate` no longer crashes when an Azure Key Vault list response carries a secret ID with no name (an empty string, a bare host, an unparsable URL): the entry is skipped like an entry with an empty name. The panic came from the Azure SDK's `ID.Name()`, which dereferences a nil pointer for those IDs, and the ID is server-controlled.
- `keyorix-migrate` no longer puts an Azure Key Vault secret value into its error output when the vault, a proxy or an impersonating endpoint answers a secret read or list with a status other than 200 and the value in the body (a 403/5xx echoing it, or a 203/206 from a proxy carrying the real body). The error now carries the status code only, and the Azure client replaces every non-200 response body with a fixed one before the SDK sees it, as the server's Azure connector already does (#4061). Listed secret IDs without a name are now reported as skipped instead of dropped.

### Testing

- **Add hostile-server fuzz targets for migrate azuresource, gcpsource, and accessplan.** `FuzzAzureSourceHostileEndpoint` drives the real `azsecrets.Client` against a TLS httptest server (VALUE-LEAK, LIVENESS, SSRF, NO-PANIC/HANG/BOUNDED-WORK oracles); `FuzzGCPSourceHostileList` drives the `gcpAPI` interface seam (GCP uses gRPC, no httptest override) with fuzz-decoded scenario structs (VALUE-LEAK, LIVENESS, NO-PANIC/HANG oracles); `FuzzAccessPlanBuild` checks `Build` for non-determinism (DETERMINISM oracle). All three targets are registered in `scripts/fuzzing/targets.d/`.
