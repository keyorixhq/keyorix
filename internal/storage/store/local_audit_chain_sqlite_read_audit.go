// local_audit_chain_sqlite_read_audit.go — which audit batches may commit on the
// SQLite read-audit connection (storage.database.audit_durability standard,
// ADR-112 Amendment 7).
//
// The connection is opened with _synchronous=NORMAL: its commits are written
// to the -wal file without an fsync, so an OS crash or power loss can lose
// them until the next FULL commit or checkpoint syncs that file. Only a batch
// whose EVERY row is a successful secret-value read audit may use it. A
// mutation, a mutation's audit row, a denied read and a batch that mixes read
// audits with anything else commit on the shared FULL pool. Rows are never
// reordered or split out to reach the NORMAL connection: chain order is batch
// order.
//
// The chain stays contiguous across the two connections because both commit
// into the same database file: one write lock (BEGIN IMMEDIATE, plus the shared
// in-process write gate) orders every append, the head is read inside the
// appending transaction, and a FULL commit's fsync of the one -wal file makes
// every earlier NORMAL commit durable too. See the amendment and
// INV-STORAGE-sqlite-normal-conn-read-audit-only.
package store

import (
	"slices"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// sqliteNormalReadAuditEventTypes are the audit event types that record a
// secret VALUE being disclosed: the same set ADR-112 Amendment 4 skips
// (internal/core's successfulValueReadEventTypes;
// TestSQLiteNormalReadAuditEventTypes_MatchCore keeps the two equal).
var sqliteNormalReadAuditEventTypes = map[string]bool{
	"secret.read":         true,
	"connect.secret_read": true,
}

// SQLiteNormalReadAuditEventTypes returns the event types whose successful rows
// may commit on the SQLite read-audit connection, sorted. For the guard test
// in internal/core.
func SQLiteNormalReadAuditEventTypes() []string {
	out := make([]string, 0, len(sqliteNormalReadAuditEventTypes))
	for t := range sqliteNormalReadAuditEventTypes {
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

// isSQLiteNormalReadAudit reports whether e is a successful secret-value read
// audit. A nil Success is not success (normalizeAuditEventForHash sets it
// before a row reaches the flusher, so this only fails closed).
func isSQLiteNormalReadAudit(e *models.AuditEvent) bool {
	return e != nil && e.Success != nil && *e.Success && sqliteNormalReadAuditEventTypes[e.EventType]
}

// isSQLiteNormalReadAuditBatch reports whether every row of batch may commit on
// the read-audit connection. An empty batch may not.
func isSQLiteNormalReadAuditBatch(batch []*auditBatchItem) bool {
	if len(batch) == 0 {
		return false
	}
	for _, item := range batch {
		if !isSQLiteNormalReadAudit(item.event) {
			return false
		}
	}
	return true
}

// auditBatchDB is the handle commitBatchAttemptTx commits batch on: the
// read-audit connection when this store has one and every row of batch is a
// successful read audit, otherwise the shared pool.
func (ls *LocalStorage) auditBatchDB(batch []*auditBatchItem) (db *gorm.DB, normal bool) {
	if ls.sqliteReadAuditDB != nil && isSQLiteNormalReadAuditBatch(batch) {
		return ls.sqliteReadAuditDB, true
	}
	return ls.db, false
}

// auditBatchTxHook, when set (tests only), runs inside every
// commitBatchAttemptTx transaction after the head read, with the transaction
// and whether it is on the read-audit connection, so a test can read PRAGMA
// synchronous on the connection the batch actually commits on.
var auditBatchTxHook func(tx *gorm.DB, normal bool)

// SetAuditBatchTxHookForTest installs auditBatchTxHook and returns the function
// that removes it. Test-only, exported for internal/storage's factory-level
// tests (that package builds the connections; this one cannot import it).
func SetAuditBatchTxHookForTest(hook func(tx *gorm.DB, normal bool)) (restore func()) {
	prev := auditBatchTxHook
	auditBatchTxHook = hook
	return func() { auditBatchTxHook = prev }
}
