// local_memdb_pool_isolation_test.go — proves the mechanism behind the "no
// such table" cascade seen in PR #1835's CI (storage-store-1) and PR #1836's
// CI (storage-store-1 AND storage-store-2, simultaneously, same run) and in
// one local run this session: a bare ":memory:" SQLite DSN opened via
// database/sql, without capping the connection pool at 1, lets Go's pool
// silently open a SECOND physical connection under concurrent load. For an
// anonymous ":memory:" DSN, that second connection is a brand-new, never-
// migrated database — any query landing on it fails "no such table",
// regardless of which table, because every table is missing on that phantom
// connection, not just one a sibling test dropped.
//
// This is a deterministic, millisecond mechanism test, not an attempt to
// catch the race in the wild: it forces the second-connection condition
// directly (hold one connection busy in an open transaction, then issue an
// independent query on the same *sql.DB) rather than hoping enough
// concurrent test load coincidentally reproduces it. A random -shuffle=on
// seed hunt (11 attempts across varied concurrency settings, including
// -race and CI's exact invocation shape) never reproduced this locally,
// which is expected: -shuffle changes test ORDER, not the timing/load
// inside a single connection-pool decision. This test controls that timing
// directly instead of gambling on it.
//
// The fix this file proves — sqlDB.SetMaxOpenConns(1) — is not new to this
// codebase: local_transaction_test.go's newTxStore already does exactly
// this, with the comment "One connection so the tx commit and the follow-up
// read share the same in-memory DB." This file makes that same reasoning
// explicit and permanent as a guard, and confirms it under genuine
// concurrent access (not just sequential reuse).
package store

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestMemDBConnectionPool_UnfixedPatternPhantomsASecondConnection reproduces
// the bug deterministically: an anonymous ":memory:" DB, migrated once, with
// the pool left at its default (unlimited) size — the exact shape all 121
// fixed call sites had before this change. While a transaction holds the
// pool's first connection open, an independent query on the same *sql.DB
// forces the pool to open a second one — which, for ":memory:", is an
// entirely separate, unmigrated database.
func TestMemDBConnectionPool_UnfixedPatternPhantomsASecondConnection(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}))

	sqlDB, err := db.DB()
	require.NoError(t, err)
	// Deliberately NOT sqlDB.SetMaxOpenConns(1) -- this is the unfixed shape.

	tx, err := sqlDB.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	// The transaction holds the pool's only existing connection. An
	// independent query on sqlDB (not through tx) cannot reuse it, so the
	// default unlimited pool opens a second one to satisfy this call
	// immediately rather than waiting.
	var count int
	err = sqlDB.QueryRow("SELECT COUNT(*) FROM projects").Scan(&count)
	require.Error(t, err,
		"an unfixed (unlimited-pool) :memory: DB must let a concurrent caller reach a second, "+
			"never-migrated phantom database instead of the migrated one")
	assert.Contains(t, err.Error(), "no such table",
		"the phantom connection has no schema at all -- any table name would fail the same way, "+
			"which is exactly the 'many unrelated tables all missing' signature seen in the real CI failures")
}

// TestMemDBConnectionPool_SetMaxOpenConnsOneSerializesInsteadOfPhantoming
// proves the fix: with the pool capped at 1, a concurrent caller cannot
// silently reach a second connection. It must wait for the transaction's
// connection to free up, then correctly see the migrated schema through
// that SAME connection -- never a phantom empty one.
//
// Deliberately runs the concurrent query on a separate goroutine, not
// inline: with SetMaxOpenConns(1), an inline call on the same goroutine
// that is holding tx open would deadlock (the goroutine would be waiting on
// itself). No production code or test in this package does that (verified
// by reading every db.Transaction(...)/WithTransaction call site in
// local_rbac.go, local_secrets.go, local_transaction.go, and
// local_webauthn.go: every one operates exclusively on the callback's own
// tx handle, never reaching back to the outer ls.db while the transaction
// is open) -- this test's two-goroutine shape exists to prove the pool
// actually serializes, not to model a real call pattern in this codebase.
func TestMemDBConnectionPool_SetMaxOpenConnsOneSerializesInsteadOfPhantoming(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1) // the fix
	require.NoError(t, db.AutoMigrate(&models.Project{}))

	tx, err := sqlDB.Begin()
	require.NoError(t, err)

	queryDone := make(chan error, 1)
	go func() {
		var count int
		queryDone <- sqlDB.QueryRow("SELECT COUNT(*) FROM projects").Scan(&count)
	}()

	select {
	case err := <-queryDone:
		t.Fatalf("concurrent query completed before the transaction released the pool's only "+
			"connection (err=%v) -- SetMaxOpenConns(1) is not actually serializing access", err)
	case <-time.After(100 * time.Millisecond):
		// Expected: the query is blocked waiting for the one connection.
	}

	require.NoError(t, tx.Commit())

	select {
	case err := <-queryDone:
		require.NoError(t, err,
			"once the transaction released the connection, the concurrent query must succeed and "+
				"see the migrated schema through that same connection, not fail or hit a phantom one")
	case <-time.After(2 * time.Second):
		t.Fatal("query never completed after the transaction committed -- SetMaxOpenConns(1) deadlocked " +
			"instead of serializing (this would be the real risk this fix carries elsewhere; it does not " +
			"occur here because the two operations run on separate goroutines, as every real caller in " +
			"this package's production code does)")
	}
}
