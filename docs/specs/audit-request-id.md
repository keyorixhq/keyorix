# Spec: request id on audit events

Status: **Proposed** (AUDIT-REQUEST-ID-1, 2026-10-23). Decided by Andrei (BACKLOG
AUDIT-REQUEST-ID, from OBS-1/OBS-2): store a request id on `audit_events`, **nullable**,
**outside the hash chain**, **server-generated**.

Related: ADR-029 (audit hash chain), ADR-097/ADR-101 (schema epoch and compatibility floor),
AUDIT-TX-2 (security mutations write their audit row inside the mutation's transaction),
`docs/operations/logging.md` (request ids in logs), `docs/rolling-upgrade-columns.md`,
DB-TUNE-1 (every audit index costs every audit INSERT).

## 1. Why

An operator investigating an incident has two records: the structured log (access log, core
error lines) and the audit trail. Today they can only be joined by time, actor and IP address,
which is ambiguous under load. A request id stored on the audit row makes the join exact:
"show me every audit row this request wrote" and "show me the log lines of the request that
wrote this audit row".

## 2. Where the id comes from

- `middleware.LogContext` (first middleware on the REST router) **always mints** the request id:
  12 random bytes, hex (24 characters). It no longer adopts the caller's `X-Request-ID`.
- A caller-supplied `X-Request-ID` is still useful to the caller (a reverse proxy's own id). It
  is sanitised exactly as before and kept as a separate log field, `client_request_id`. It is
  never written to the audit row and never echoed as our id.
- The response's `X-Request-ID` header carries the server's id, so "what was the id of the
  failing call" is still answerable from the client side. The request header is overwritten
  with the server's id so chi's `RequestID` middleware adopts it.
- `logging.Holder` records whether its id was minted by the server
  (`SetServerRequestID`) or set from outside (`SetRequestID`, used by the recovery
  middleware's fallback). Only a server-minted id is offered to the audit writer
  (`logging.ServerRequestID(ctx)`), so a later code path that records an external value in the
  holder cannot leak it into an audit row.
- gRPC requests carry no request id yet (they get no holder): their audit rows have NULL.
  Scheduler jobs, startup events and other non-request writers also have NULL. NULL means
  "no request", never "unknown request".

Behaviour change for operators: a proxy that sets `X-Request-ID` used to see that value as
`request_id` in our logs; now it appears as `client_request_id`, and `request_id` is ours.

## 3. How the id reaches the audit row

The single funnel for every audit append is `LocalStorage.logAuditEvent`
(`internal/storage/store/local_audit_chain.go`): `LogAuditEvent` and
`LogAuditEventWithAccessLog`, on the root storage (batched flusher) and on a transaction-scoped
clone (the AUDIT-TX-2 in-transaction path, direct). Every core writer (`writeAuditEvent*`,
`audit_target.go`, `secret_mutation_audit.go`), `server/admin` and startup events reach it.

`logAuditEvent` sets `event.RequestID` from `logging.ServerRequestID(ctx)` **unconditionally**
(NULL when the context has none), next to the existing pre-hash normalisation and before the
event is queued to the flusher. Consequences:

- no handler or core writer changes; a new writer gets the id for free;
- a caller cannot choose the value: whatever a writer put in `RequestID` is replaced;
- detached audit writes keep it, because `core.DetachedAuditContext` already carries the
  request's `logging.Holder`.

Not covered (NULL): owed audit rows that `pending_audit_events` backfills later run on the
scheduler's context. Carrying the original id through the owed-row JSON is a follow-up
(section 9).

## 4. The column

`audit_events.request_id TEXT NULL`, model field `RequestID *string`. Values are at most 24
characters today (the cap of `logging.SanitizeID`, 128, still bounds anything a future id
format could produce).

**No index.** The lookup "rows of request X" is a rare, operator-driven incident query. The
id is a random key, which is the exact cost profile DB-TUNE-1 removed for `prev_hash` /
`entry_hash`: a random-key b-tree on the hottest INSERT in the system (one per secret read).
Rows of one request are written within milliseconds of each other, so the filter is served by
the existing `(event_time, id)` index when the caller gives a time window, which the API
documentation will recommend (section 8). If a measured need appears, add a partial index
(`WHERE request_id IS NOT NULL`) through `AuditListIndexes` (built `CONCURRENTLY` on Postgres).

## 5. Outside the hash chain: what that means for tamper evidence

`computeAuditEntryHash` (and its offline twin `auditverify.ComputeEntryHash`) do **not** hash
`request_id`, like `machine_identity_id` today. Reasons: the hash encoding stays unchanged, so
no chain re-encoding, no second encoding to verify, no mixed-version window in which old
replicas write rows a new verifier would hash differently; and a NULL written by an old
replica is indistinguishable from "no request", so there is nothing to reconcile.

Said plainly: **anyone with write access to the database can set, change or clear
`request_id` on any row, and neither `VerifyAuditChain`, the signed checkpoints nor
`admin verify-audit` will notice.** They can therefore make an audit row point at the wrong
request's log lines.

Decision: **`request_id` is advisory**, documented as such, with no separate per-row integrity
mechanism. Why that is acceptable:

- it is a correlation hint, never evidence: no authorization, attribution, retention or
  verification decision reads it. Who, what, when, from where (actor, event type, target,
  time, IP) stay hash-covered;
- an investigator joins on `request_id` and then confirms the join on the hash-covered fields
  (the log line's principal, route and time must match the audit row's actor, event type and
  time). The docs say so;
- copies that the database attacker cannot rewrite exist where they matter: the SIEM
  forwarder sends `request_id` with each event at write time (off-box), and a backup archive's
  per-table SHA-256 sits inside the HMAC-signed manifest;
- a per-row MAC (rejected) would need a DEK-derived key on the write path, a new verifier and
  key-rotation handling for a field that decides nothing; the chain itself (rejected) would
  break the "outside the chain" decision and force a chain-encoding migration.

## 6. Migration and rolling upgrade

- `migrateDatabase` adds the column when missing:
  `ALTER TABLE audit_events ADD COLUMN request_id TEXT` on both backends. On PostgreSQL a
  nullable column with no default is a catalog-only change: no table rewrite, a brief
  `ACCESS EXCLUSIVE` lock for the catalog update only. On SQLite `ADD COLUMN` does not rewrite
  the table either. Fresh installs get it from `AutoMigrate`.
- **Schema epoch 6, floor unchanged (3).** An epoch-5 replica during a rolling upgrade never
  reads the column (`QueryFields`, INV-STORE-explicit-column-reads) and inserts without it, so
  its rows have NULL: exactly the "no request id" meaning, nothing to repair, nothing an
  epoch-6 binary relies on. A one-release rollback keeps working the same way.
  `TestCurrentSchemaEpoch_Is6_SeeADR101` and the epoch-6 schema snapshots record the decision.
- ADR-101's status paragraph lists each epoch; the epoch-6 line is coordinator text (no ADR
  edits in this PR).

## 7. Backup, restore, export, verify

- **Backup format:** unchanged, `FormatVersion` stays 2. The v2 archive records each table's
  column list, so the new column is archived with its values. Restoring an older archive
  (no `request_id`) yields NULL. An epoch-5 binary refuses an archive that has the column
  (`checkSchemaDelta`), which is the existing, loud cross-version behaviour.
- **SIEM forwarder:** `request_id` is in the event payload (omitted when NULL).
- **Verify (online and `admin verify-audit`):** ignores the column. The hash functions do not
  read it; the offline verifier's explicit column list does not select it.
- **Audit export (`/audit/export`, `.csv`):** include `request_id` (section 8, follow-up PR).

## 8. API and CLI surface (AUDIT-REQUEST-ID-2)

- `GET /api/v1/audit/logs`, `/audit/search`, `/audit/export`: `request_id` on each entry
  (omitted when NULL); `/audit/export.csv` gets a `request_id` column (formula-escaped like
  every text column).
- Filter `request_id=<id>` (exact match) on `/audit/logs` and `/audit/search`, plus
  `storage.AuditFilter.RequestID`. Documentation recommends a time window with it.
- gRPC `AuditService`: same field and filter; the CLI `keyorix audit logs` gets
  `--request-id` and shows the id in `-o json` / wide output.
- The OpenAPI and proto edits are in hot wiring files, so they ship as their own PR.
- Shipped as specified, with these details: the filter is also ignored when empty
  (`request_id=` matches nothing special), `/audit/export` (JSON) carries the field but takes
  no filter (it is the after_id-paged SIEM feed), `export.csv`'s new column is last so
  existing positional readers keep working, and the CLI shows the id with `--wide` rather
  than widening the default table.

## 9. Acceptance criteria (this PR)

1. `entry_hash` of an event is identical with and without `request_id`
   (`computeAuditEntryHash` and `auditverify.ComputeEntryHash`).
2. `VerifyAuditChain` passes on a chain that mixes NULL and set request ids, and still passes
   after `request_id` is edited directly in the database (documents the advisory status).
3. Migration up on a populated database (old schema without the column, existing chained
   rows): the column appears, old rows are NULL, the chain still verifies; SQLite always,
   PostgreSQL with `KEYORIX_TEST_PG_DSN`.
4. An authenticated API call that writes an audit row stores the server's request id: equal
   to the response's `X-Request-ID`, 24 hex characters, and **not** the `X-Request-ID` the
   client sent.
5. A writer cannot choose the value: an event submitted with `RequestID` set and no server id
   in the context is stored with NULL.
6. Mixed-version (epoch-5 replica next to epoch-6): `scripts/e2e/mixed_version_test.go`
   needs Docker; pending the e2e VM. The unit-level stand-in is criterion 3 plus the
   QueryFields guard.

Follow-ups: section 8; carry the request id through `pending_audit_events` for owed rows;
gRPC request ids (interceptor minting the same id into a holder).

## 10. Owed audit rows and gRPC (AUDIT-REQUEST-ID-2)

- **gRPC:** `interceptors.RequestIDInterceptor` / `StreamRequestIDInterceptor` run right
  after Recovery, put a `logging.Holder` on the call's context and mint the id there
  (`SetServerRequestID`, 24 hex characters, the same shape as HTTP), so `logAuditEvent` stamps
  gRPC-written rows like any other. The id is returned in the `x-request-id` response header;
  a client-sent `x-request-id` is kept only as `client_request_id`, so it can never reach the
  column. If the system random source fails, the call carries no id and its rows are NULL.
- **Owed rows:** `pending_audit_events.request_id TEXT NULL` records
  `logging.ServerRequestID(ctx)` wherever a pending record is written (the plain-suspend and
  `withOwedAuditMutation` paths, their late-queue fallbacks, and the degraded break-glass
  commit). `BackfillPendingAuditEvents` appends each row under a fresh holder carrying the
  recorded id (`owedBackfillContext`), so the single stamping point stays `logAuditEvent` and
  a writer still cannot choose the value. A record without an id appends NULL even if the
  backfill itself runs inside a request: a late row never takes the id of the pass that
  writes it.
- **Migration:** `ALTER TABLE pending_audit_events ADD COLUMN request_id TEXT` on both
  backends (catalog-only on PostgreSQL). **Schema epoch 8, floor unchanged (3):** an epoch-7
  replica never writes the column, so its owed records have NULL and backfill as "no request
  id", exactly what they had before.
- Tests: `TestOwedAudit_BackfilledRowKeepsTheRequestID`,
  `TestBreakGlass_DegradedOwedRowsKeepTheRequestID`,
  `TestPendingAuditRequestID_AddedOnUpgrade_SQLite` / `_Postgres_AddedOnUpgrade`,
  `TestGRPCMutation_AuditRowCarriesServerMintedRequestID`.
- **Not done here, found on the way:** the failed-login audit row (`auth.login_failed`) is
  written by the login handler from a goroutine on `context.Background()`
  (`server/http/handlers/auth.go`), so it carries no request id. Using
  `core.DetachedAuditContext(r.Context())` there (which keeps the holder) would stamp it.
