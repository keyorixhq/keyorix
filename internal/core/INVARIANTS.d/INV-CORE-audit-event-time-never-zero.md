- **INV-CORE-audit-event-time-never-zero** Every audit event emitted through core
  (`emitAudit`, `emitAuditOn`, `emitAuditWithAccessLog`, owed events, secret-mutation
  audits — all via `prepareAuditEventForEmit`) is stored with a non-zero `EventTime`: one the
  emitter left unset is defaulted to now, UTC, truncated to microseconds, BEFORE the storage
  write hashes the row, so the hashed and stored instant are the same and verify-audit
  recomputes the same entry hash. An `EventTime` the emitter set is not touched. The default
  lives at the core choke point, deliberately not in the storage audit write path. Why:
  FIX-3088 — a zero-time row (0001-01-01) carries a seconds-resolution local-mean-time
  offset on a non-UTC host, and a Postgres backup/restore round trip broke audit row 1.
  Guard: `audit_zero_event_time_test.go` `TestEmitAudit_ZeroEventTimeIsStoredAsNowAndVerifies`
  (stored non-zero, within the emit window, µs precision; an explicit time kept; the chain
  verifies). **Not covered**: writers that call `storage.LogAuditEvent` directly, bypassing
  core (`server/main.go`, `server/admin`, `anomaly.go`'s detector); each sets `EventTime`
  itself today.
