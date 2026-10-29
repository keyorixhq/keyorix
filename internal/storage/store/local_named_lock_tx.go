// local_named_lock_tx.go — LockNamedKeyInTx, the transaction-scoped half of
// WithNamedLock (NAMEDLOCK-OVERLAP-2; option E of docs/design/pooler-lock-loss.md,
// applied to the write transaction only).
package store

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// errNamedKeyOutsideTx is returned when LockNamedKeyInTx is called on a
// LocalStorage that is not the transaction-scoped handle WithTransaction hands
// fn. A transaction-scoped advisory lock taken in an autocommit statement is
// released when that statement ends, so it would fence nothing: fail closed
// instead of answering as if it had.
var errNamedKeyOutsideTx = errors.New("LockNamedKeyInTx called outside a transaction")

// namedLockXactKey derives LockNamedKeyInTx's lock from the same FNV-1a hash
// namedLockKey gives WithNamedLock, split into PostgreSQL's two-int4 advisory
// key space. That space does not overlap the one-bigint space WithNamedLock's
// session lock uses (PostgreSQL docs, "Advisory Locks"), and it must not: the
// session lock lives on a lock-pool connection (SetNamedLockDB) while the
// transaction runs on a request-pool connection, a different backend. On the
// same bigint key, a holder's own transaction would wait for its own session
// lock, which is released only after that transaction returns: a permanent
// self-deadlock. Guard: TestLockNamedKeyInTx_Postgres_InsideOwnNamedLockDoesNotSelfDeadlock.
func namedLockXactKey(lockKey string) (hi, lo int32) {
	k := uint64(namedLockKey(lockKey)) // #nosec G115 -- bit reinterpretation of the same hash, not a range conversion
	return int32(k >> 32), int32(k)    // #nosec G115 -- advisory-lock key halves, truncation intended
}

// LockNamedKeyInTx takes a transaction-scoped lock on lockKey inside the
// transaction this LocalStorage is bound to; see storage.LockingStore for the
// contract.
//
// PostgreSQL: pg_advisory_xact_lock on namedLockXactKey(lockKey). It blocks
// until every other transaction holding the key has committed or rolled back,
// honours ctx while it waits, and is released by PostgreSQL itself when this
// transaction ends, so it cannot outlive the write it fences (unlike
// WithNamedLock's session lock, whose loss the holder learns about only at the
// next liveness ping). Re-taking a key this transaction already holds returns
// at once (advisory locks are re-entrant per backend).
//
// SQLite: nothing to take. Every write transaction is BEGIN IMMEDIATE and the
// process is the only writer (the same reason WithNamedLock's in-process queue
// is its whole guarantee there), so any two write transactions already run one
// after the other, whatever their keys. The transaction check still applies,
// so a caller that takes the fence on the wrong handle fails in SQLite tests
// too, not only on PostgreSQL.
func (ls *LocalStorage) LockNamedKeyInTx(ctx context.Context, lockKey string) error {
	if committer, ok := ls.db.Statement.ConnPool.(gorm.TxCommitter); !ok || committer == nil {
		return fmt.Errorf("named lock %q: %w", lockKey, errNamedKeyOutsideTx)
	}
	if ls.db.Dialector.Name() != "postgres" {
		return nil
	}
	hi, lo := namedLockXactKey(lockKey)
	if err := ls.db.WithContext(ctx).Exec("SELECT pg_advisory_xact_lock(?, ?)", hi, lo).Error; err != nil {
		return fmt.Errorf("failed to acquire transaction named lock %q: %w", lockKey, err)
	}
	return nil
}
