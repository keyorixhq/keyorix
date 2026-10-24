package serverguard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/keyorixhq/keyorix/internal/config"
)

// keyInitLockKey is the PostgreSQL advisory-lock key a server takes, with
// storage.encryption.key_dir_lock: database, around the start-up steps that may
// write key files: DEK-rotation crash recovery and first-boot key generation
// (docs/multi-replica-keys.md). Distinct from serverPresenceLockKey (872342)
// and postgresMigrationLockKey (872341).
const keyInitLockKey = 872343

// keyInitPollInterval is how often WithKeyInitLock retries a held lock.
const keyInitPollInterval = 200 * time.Millisecond

// WithKeyInitLock runs fn while holding the key-initialisation advisory lock
// on cfg's PostgreSQL database, waiting up to wait for another holder (a
// sibling replica generating or recovering the shared key files) to finish.
// It replaces, for key_dir_lock: database, the exclusive flock(2) a server
// otherwise holds on dek.lock across the same steps: two replicas booting on
// one fresh key directory serialise here instead of on the filesystem, and
// the second then loads the key files the first wrote rather than generating
// its own.
//
// The lock is released when fn returns. It is not held for the server's
// lifetime: the shared server-presence lock (AcquirePresence) is what keeps
// key-changing admin commands out while a server runs. A lock lost while fn
// runs is an error even when fn succeeded (keyInitLockStillHeld).
//
// PostgreSQL only; any other storage type is an error (config validation
// already refuses key_dir_lock: database there). Under a transaction-mode
// pooler the lock is transaction-scoped inside a pinned transaction, like the
// presence lock (pgLockSQL).
func WithKeyInitLock(cfg *config.Config, wait time.Duration, fn func() error) error {
	switch cfg.Storage.Type {
	case "postgres", "postgresql":
	default:
		return fmt.Errorf("key-initialisation lock needs PostgreSQL storage (storage.type %q)", cfg.Storage.Type)
	}
	sqlDB, conn, err := pgConn(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = sqlDB.Close() }()
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	xact := cfg.Storage.Database.TransactionPooling()
	if xact {
		if err := beginPinnedLockTx(ctx, conn); err != nil {
			return fmt.Errorf("acquire key-initialisation advisory lock: %w", err)
		}
	}
	tryLock := pgLockSQL("pg_try_advisory_lock", xact)
	for {
		var acquired bool
		if err := conn.QueryRowContext(ctx, tryLock, keyInitLockArgs(xact)...).Scan(&acquired); err != nil {
			return fmt.Errorf("acquire key-initialisation advisory lock: %w", err)
		}
		if acquired {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("another replica has held the key-initialisation lock (postgres advisory lock %d) for more than %s; it is generating or recovering the shared key files -- retry when it has started", keyInitLockKey, wait)
		case <-time.After(keyInitPollInterval):
		}
	}
	defer func() {
		relCtx, relCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer relCancel()
		if xact {
			endPinnedLockTx(relCtx, conn)
			return
		}
		// A failed unlock is still released when conn closes (deferred above).
		_, _ = conn.ExecContext(relCtx, "SELECT pg_advisory_unlock($1)", keyInitLockKey)
	}()
	return runHoldingKeyInitLock(conn, xact, fn)
}

// keyInitLockStillHeld returns an error unless this connection's backend still
// holds the key-initialisation lock. The lock ends with its backend or, under a
// transaction-mode pooler, its transaction (pg_terminate_backend, a PostgreSQL
// restart or failover, a pooler timeout) with no signal to the holder, and a
// sibling replica can then run its own key generation beside fn. Checked once,
// after fn (runHoldingKeyInitLock): it cannot stop that sibling, but it keeps
// this replica from reporting success and serving under a DEK the sibling may
// have overwritten on the shared key directory (the caller refuses to start; a
// restart loads whatever the key directory then holds, and the DEK epoch guard
// judges it). Unlike a ping it also sees a lock that ended on a connection that
// is still alive, which is what a transaction-mode pooler does.
func keyInitLockStillHeld(conn *sql.Conn, xact bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const q = `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted
		AND pid = pg_backend_pid() AND objsubid = 1 AND classid = $1 AND objid = $2)`
	args := []any{int64(keyInitLockKey >> 32), int64(keyInitLockKey & 0xFFFFFFFF)}
	if xact {
		args = append([]any{pgx.QueryExecModeSimpleProtocol}, args...)
	}
	var held bool
	err := conn.QueryRowContext(ctx, q, args...).Scan(&held)
	if err == nil && held {
		return nil
	}
	detail := "no longer held by this connection"
	if err != nil {
		detail = err.Error()
	}
	return fmt.Errorf("%w (%s)", errKeyInitLockLost, detail)
}

// errKeyInitLockLost is returned (joined with fn's own error) when the
// key-initialisation lock ended while fn ran: its database session died, or the
// lock stopped being held by it.
var errKeyInitLockLost = errors.New("the key-initialisation lock was lost while this replica was generating or recovering the key files, so another replica may have written them at the same time; refusing to start with keys that may not match the key directory -- restart to load the files now on disk (docs/multi-replica-keys.md)")

// runHoldingKeyInitLock runs fn while watching conn, which holds the
// key-initialisation lock, and checks it once more when fn returns: fn is
// usually shorter than one watch interval, and a loss at any point means a
// sibling replica could have generated or recovered the key files beside this
// one. Either way the caller gets errKeyInitLockLost and must not start with
// the keys fn loaded (INV-STORAGE-session-advisory-lock-loss).
func runHoldingKeyInitLock(conn *sql.Conn, xact bool, fn func() error) error {
	var lost atomic.Bool
	stop := config.WatchPinnedLockConn(conn, keyInitLockWho, func(error) { lost.Store(true) })
	err := fn()
	stop() // before the final check, which needs the connection to itself
	if !lost.Load() {
		if herr := keyInitLockStillHeld(conn, xact); herr != nil {
			config.ReportAdvisoryLockLost(keyInitLockWho, herr)
			lost.Store(true)
		}
	}
	if lost.Load() {
		return errors.Join(err, errKeyInitLockLost)
	}
	return err
}

// keyInitLockWho names the key-initialisation lock in the lock-loss log line.
const keyInitLockWho = "key-initialisation lock"

// keyInitLockArgs is pgLockArgs with keyInitLockKey in place of the presence key.
func keyInitLockArgs(xact bool) []any {
	args := pgLockArgs(xact)
	args[len(args)-1] = keyInitLockKey
	return args
}
