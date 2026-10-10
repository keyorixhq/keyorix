- **INV-STORE-audit-actor-kind-filter-matches-display** `GetAuditLogs`' `actor_type`
  filter and the `system` branch of its `actor` search select exactly the rows
  `storage.AuditActorKind` (internal/core/storage/audit_actor_kind.go) displays as that
  kind, on SQLite and Postgres; HTTP and gRPC display the kind through that same
  function. A row with no acting user is `system` only when nothing identifies a
  principal (no user, machine identity, impersonator or client IP, and not an
  `auth.*`/`mfa.*`/`webauthn.*` event), so failed logins stay under `user`. Display
  only: the stored, hash-covered `actor_type` is never rewritten, and the chained JSON
  export (`/api/v1/audit/export`) emits it verbatim beside `actor_kind_display`.
  Why: #2951 and its review on #2960 (gRPC showed the raw kind; failed logins were
  relabelled `system`; the export's rewritten `actor_type` failed re-hashing).
  Guard: `TestAuditActorKindWhere_AgreesWithAuditActorKind` (+ `_Postgres`, pg-gated),
  `TestGetAuditLogs_ActorSearchFindsSystemRows` (+ `_Postgres`),
  `internal/core/storage` `TestAuditActorKind_SystemOnlyWithoutAnyPrincipal`,
  `server/grpc/services` `TestAuditService_GetAuditLogs_ActorKindMatchesFilter`,
  `server/http/handlers` `TestExportAuditLogs_RehashesWithStoredActorTypeAndShowsKindSeparately`.
