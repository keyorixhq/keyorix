- **INV-CORE-secret-read-means-value-disclosure** A `secret.read` audit event (and an
  access-log row of action `read`) is written only when a secret's value is disclosed,
  with ONE known exception: the by-name metadata lookup (HTTP `GET /secrets/by-name`,
  `SecretHandler.GetSecretByName`) returns metadata only but still writes `secret.read`
  (fire-and-forget, `LogSecretReadWithProject`). It is kept as-is on purpose: removing
  that audit row would drop a record of who resolved which secret by name, and the CLI
  follows it with the by-id value read anyway. That path is UNGUARDED (no test pins it
  either way); converting it to a metadata-lookup event is a follow-up. Listing a secret's version history (HTTP `GET /secrets/{id}/versions`, gRPC
  `GetSecretVersions`) returns metadata only (`SecretVersion.EncryptedValue` is
  `json:"-"`) and is audited as `secret.versions_listed` with access-log action
  `versions_list`, through the same atomic, audit-before-response writer
  (`LogSecretVersionsListed` → `emitAuditWithAccessLog`). Read counts, billing/usage reads,
  read summaries and the dashboard's "accessed" all key on `secret.read` / action `read`,
  so a listing never counts as a read; anomaly detection reads every access-log action, so
  it still sees who listed versions from where. Why: AUDIT-UX-2 (#2951 follow-up):
  `keyorix secret delete` previews the version count and so wrote a `secret.read` for the
  secret it was deleting. Guard: `server/http` `TestCLISecretDeleteFlow_WritesNoSecretRead`
  (the CLI delete request sequence against the real router), `server/grpc/services`
  `TestSecretService_GetSecretVersions_AuditsListingNotRead`.
