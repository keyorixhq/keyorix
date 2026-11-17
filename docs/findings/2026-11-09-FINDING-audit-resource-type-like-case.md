# FINDING 2026-11-09: audit `resource_type` filter is case-insensitive on SQLite only

Classification: **DEFECT, low**. Not a security defect. Found by `FuzzStorageIfaceDifferential`.

## What differs

`GetAuditLogs` applies `AuditFilter.ResourceType` as `event_type LIKE ? ESCAPE '\'`
(`internal/storage/store/local_audit_list.go:253`) with the term `escapeLIKE(term) + ".%"`.
The same SQL has different semantics per backend:

- SQLite's `LIKE` is case-insensitive for ASCII, so `Secret` matches `secret.read`.
- PostgreSQL's `LIKE` is case-sensitive, so `Secret` matches nothing.

`foldedContainsClause` (`search_fold.go`) exists to remove exactly this kind of difference
for the other search columns; the resource-type predicate does not use it, and the
surrounding comment (`local_audit_list.go:213-216`) describes the problem only for the
actor filter.

## Minimal reproduction

Program of two steps, deterministic, driving the storage interface directly:

1. `LogAuditEvent` with event type `secret.read`.
2. `GetAuditLogs(ResourceType: "Secret")`, reading every page.

Result: SQLite returns the row (total 1), PostgreSQL returns none (total 0). Test:
`TestIfaceKnownFinding_AuditResourceTypeLikeCase` runs the program with the gate on and
with `IFACE_DIFF_STRICT=1`. It was replayed by the harness on PostgreSQL 16.15, on a
database with `C` collation and ctype.

## Reachability

`GET /api/v1/audit/search?resource_type=` passes the query value through unchanged
(`server/http/handlers/audit_search.go:106`, `internal/core/audit_search.go:137`), as does
`keyorix audit search --resource-type`. A client that sends a differently cased value gets
results on SQLite and an empty list on PostgreSQL. The CLI help and handler comments
use lowercase resource kinds, so the common case (`secret`) matches on both backends.

## Impact

A case-variant resource filter returns a different row set per backend. The audit log
itself is unaffected: every row is still stored and returned by other filters. Consumers
of the search get an empty result on PostgreSQL where SQLite would answer, not a wider one,
so this is not an authorization or disclosure problem.

## Fixed (AUDIT-SEARCH-PARITY-1, #4090)

`resource_type` is now matched case-sensitively on both backends: `GLOB` on SQLite,
`LIKE` on PostgreSQL, each against the raw term (event types are lower-case constants, so a
differently cased value is a caller error and matches nothing). The `ifaceKnownFindings`
row and `TestIfaceKnownFinding_AuditResourceTypeLikeCase` were removed with the fix.
