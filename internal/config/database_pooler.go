package config

import (
	"fmt"

	"github.com/jackc/pgx/v5"
)

// storage.database.pooler values (docs/postgresql-poolers.md). The setting names
// the connection pooler between Keyorix and PostgreSQL. A pooler cannot be
// detected reliably from the client side (PgBouncer's SHOW pool_mode answers
// only on its admin console), so the operator states it.
const (
	// PoolerNone (also the empty value, the default) is a direct connection,
	// or a pooler that pins one server connection to each client connection
	// for its whole life. Nothing changes.
	PoolerNone = "none"
	// PoolerPgBouncerSession is PgBouncer in pool_mode=session. A client
	// connection keeps one server connection, so it behaves like a direct
	// one; the value exists so the configuration says what is deployed.
	// Nothing changes at runtime.
	PoolerPgBouncerSession = "pgbouncer-session"
	// PoolerPgBouncerTransaction is PgBouncer in pool_mode=transaction: a
	// client connection holds a server connection only for one transaction.
	// See TransactionPooling for what that changes.
	PoolerPgBouncerTransaction = "pgbouncer-transaction"
)

// TransactionPooling reports whether storage.database.pooler says a
// transaction-mode pooler sits in front of PostgreSQL. When it does:
//
//   - every pgx connection runs statements in QueryExecModeExec, with no
//     statement or description cache (ResolvePostgresConnConfig), so nothing
//     depends on a named prepared statement that lives on one server
//     connection;
//   - every advisory lock the server holds across statements is taken as a
//     transaction-scoped lock inside a transaction kept open for the whole
//     critical section (the pooler keeps a client on one server connection
//     for exactly as long as a transaction is open), instead of a
//     session-scoped lock, which would be left on whatever server connection
//     the statement happened to run on.
func (d *DatabaseConfig) TransactionPooling() bool {
	return d.Pooler == PoolerPgBouncerTransaction
}

// validatePooler refuses an unknown storage.database.pooler value, and any
// value other than none on a backend without a PostgreSQL connection, rather
// than ignoring it.
func validatePooler(storageType string, d *DatabaseConfig) error {
	switch d.Pooler {
	case "", PoolerNone:
		return nil
	case PoolerPgBouncerSession, PoolerPgBouncerTransaction:
		if storageType != "postgres" && storageType != "postgresql" {
			return fmt.Errorf("storage.database.pooler %q applies only to storage.type postgres; remove it", d.Pooler)
		}
		return nil
	default:
		return fmt.Errorf("storage.database.pooler %q is not supported; use %q, %q or %q (see docs/postgresql-poolers.md)",
			d.Pooler, PoolerNone, PoolerPgBouncerSession, PoolerPgBouncerTransaction)
	}
}

// applyPoolerConnConfig sets the pgx execution mode a transaction-mode pooler
// needs. pgx's default caches a named prepared statement per query on the
// server connection it prepared it on; behind transaction pooling the next
// statement may run on another server connection, where that name does not
// exist (or, with PgBouncer's own prepared-statement tracking, is re-prepared
// on every server connection). QueryExecModeExec sends each statement with
// the extended protocol and an unnamed statement in one round trip, and needs
// no state on the server connection between statements.
func applyPoolerConnConfig(d *DatabaseConfig, cc *pgx.ConnConfig) {
	if !d.TransactionPooling() {
		return
	}
	cc.DefaultQueryExecMode = pgx.QueryExecModeExec
	cc.StatementCacheCapacity = 0
	cc.DescriptionCacheCapacity = 0
}
