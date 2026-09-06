// local_sod_grant_lock.go — serializes every separation-of-duties-gated role
// grant/join path's preventive check-then-write sequence across replicas
// (#419/#G04-HA).
//
// AssignUserRole, assignUserRoleSystemGrant, AssignUserRoleWithExpiry,
// AssignRoleToGroup, AssignGroupRoleWithExpiry, and AddUserToGroup's
// validateGroupJoinRoles path were previously guarded only by a
// KeyorixCore-level sync.Mutex (sodGrantMu), which serializes concurrent
// callers within ONE server process but does nothing for two different
// replicas of an HA deployment racing a grant against the SAME principal on
// the same shared database: each replica's mutex only guards its own
// process, so both can read a pre-grant permission set that doesn't yet
// reflect the other's still-uncommitted grant, both pass the preventive
// check, and together create the exact toxic-permission overlap the policy
// exists to block.
package store

import (
	"context"
	"fmt"
)

// sodGrantAdvisoryLockKey is the Postgres advisory-lock key guarding the SoD
// preventive-check-then-write sequence across processes. Distinct from every
// other advisory-lock key in this package — the critical sections are
// independent and must not contend with each other.
const sodGrantAdvisoryLockKey = 0x4B455941_534F4447 // "KEYASODG"

// WithSoDGrantLock runs fn with a SoD-gated grant/join's check-then-write
// sequence serialized: a process-level mutex covers the common single-writer
// self-host topology and SQLite (inherently single-instance — there is no
// DB-level advisory lock to take); a PostgreSQL session-scoped advisory lock
// (pg_advisory_lock) extends that across processes/replicas (ADR-039 HA).
//
// Deliberately ONE shared lock across every SoD-gated path (not one per
// principal) — mirroring the single in-process mutex it replaces, so e.g. a
// group-role grant affecting a member and that same member's own concurrent
// direct grant still serialize against each other, not just against
// themselves.
//
// Like WithBootstrapLock/WithAuditCheckpointLock, this BLOCKS until the lock
// is acquired rather than skipping on contention — a replica that loses the
// race must actually re-run its preventive check under the lock and observe
// the winner's now-committed grant, not silently no-op.
func (ls *LocalStorage) WithSoDGrantLock(ctx context.Context, fn func() error) error {
	ls.sodGrantMu.Lock()
	defer ls.sodGrantMu.Unlock()

	if ls.db.Dialector.Name() != "postgres" {
		return fn()
	}

	sqlDB, err := ls.db.DB()
	if err != nil {
		return err
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }() // returns the conn to the pool (after the unlock below)

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", int64(sodGrantAdvisoryLockKey)); err != nil {
		return fmt.Errorf("failed to acquire SoD-grant advisory lock: %w", err)
	}
	// Release before the deferred Close so the pooled connection carries no lock.
	defer func() {
		_, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", int64(sodGrantAdvisoryLockKey))
	}()

	return fn()
}
