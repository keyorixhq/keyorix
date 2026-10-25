- **INV-STORE-audit-request-id-server-stamped-unhashed** `audit_events.request_id` is
  written in exactly one place, `logAuditEvent` (`stampAuditRequestID`), from
  `logging.ServerRequestID(ctx)`: the id the server minted for the request, or NULL.
  Whatever a writer put in `RequestID` is overwritten, and an id recorded in the
  request's log holder from outside (`SetRequestID`, a client header) is never returned
  by `ServerRequestID`. The column is not a hash input (`computeAuditEntryHash`,
  `auditverify.ComputeEntryHash`), so it is advisory: a database writer can change it
  undetected, and verification is unaffected by NULL or set values.
  Why: AUDIT-REQUEST-ID-1, docs/specs/audit-request-id.md (Andrei: nullable, outside
  the hash chain, server-generated).
  Guard: `TestLogAuditEvent_StampsOnlyServerMintedRequestID`,
  `TestAuditEntryHash_IgnoresRequestID`,
  `TestVerifyAuditChain_MixedRequestIDs_AndEditIsUndetected`,
  `internal/logging` `TestServerRequestID_OnlyServerMinted`,
  `server` `TestJSONLogs_ShapeCorrelationAndNoSecrets` (real server: the audit row
  carries the echoed server id, never the caller's `X-Request-ID`).
