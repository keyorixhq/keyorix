// local_scheduler_lock.go — single-replica gating for background schedulers
// (ADR-039 HA). On PostgreSQL a session-scoped advisory lock ensures only one
// replica runs a given periodic job (purge, dynamic-secrets sweep, anomaly
// detection) per tick; on SQLite (inherently single-instance) the job always runs.
package store

import (
	"context"
	"fmt"
)

// runProtected runs a scheduler job, converting a panic into an error so a single
// bad tick can't kill the scheduler goroutine (and so the advisory lock is still
// released by the caller's defers). Mirrors that the pre-ADR-039 schedulers had no
// panic guard either, but this is now the natural choke point to add one.
func runProtected(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("scheduler job panicked: %v", r)
		}
	}()
	return fn()
}

// WithSchedulerLock runs fn iff this process can acquire the advisory lock `key`.
//
// PostgreSQL: takes a session advisory lock on a dedicated pooled connection via
// pg_try_advisory_lock. If another replica holds it, returns (false, nil) so the
// caller skips this tick. The lock is always released (pg_advisory_unlock) before
// the connection returns to the pool — a session lock would otherwise outlive the
// tick on the pooled connection.
//
// SQLite / non-Postgres: there is only one instance, so fn always runs.
func (ls *LocalStorage) WithSchedulerLock(ctx context.Context, key int64, fn func() error) (bool, error) {
	if ls.db.Dialector.Name() != "postgres" {
		return true, runProtected(fn)
	}
	sqlDB, err := ls.db.DB()
	if err != nil {
		return false, err
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close() // returns the conn to the pool (after the unlock below)

	var locked bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&locked); err != nil {
		return false, err
	}
	if !locked {
		return false, nil // another replica is running this job — skip
	}
	// Release before the deferred Close so the pooled connection carries no lock.
	defer func() { _, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", key) }()
	return true, runProtected(fn)
}
