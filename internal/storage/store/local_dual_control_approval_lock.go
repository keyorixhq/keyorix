// local_dual_control_approval_lock.go — serializes
// ApproveAccessRequestWithExpiry's read-approvals-decide-grant sequence
// across replicas (#419/#G04-HA).
//
// Two approvers signing off at the exact K-of-N dual-control threshold
// boundary on DIFFERENT replicas of an HA deployment can otherwise each read
// the same below-threshold approval count before either's approval row
// commits, both compute "received == required", and both finalize the
// grant — defeating the K-distinct-approvers dual-control guarantee with
// fewer than K approvals actually recorded first.
package store

import (
	"context"
	"fmt"
)

// dualControlApprovalAdvisoryLockKey is the Postgres advisory-lock key
// guarding ApproveAccessRequestWithExpiry's read-decide-grant sequence across
// processes. Distinct from every other advisory-lock key in this package.
const dualControlApprovalAdvisoryLockKey = 0x4B455941_4443414C // "KEYADCAL"

// WithDualControlApprovalLock runs fn with ApproveAccessRequestWithExpiry's
// whole read-approvals-decide-grant sequence serialized: a process-level
// mutex covers the common single-writer self-host topology and SQLite
// (inherently single-instance — there is no DB-level advisory lock to take);
// a PostgreSQL session-scoped advisory lock (pg_advisory_lock) extends that
// across processes/replicas (ADR-039 HA).
//
// Like WithBootstrapLock/WithAuditCheckpointLock, this BLOCKS until the lock
// is acquired rather than skipping on contention — a replica that loses the
// race must actually re-count approvals under the lock and observe the
// winner's now-committed approval/grant, not silently no-op.
func (ls *LocalStorage) WithDualControlApprovalLock(ctx context.Context, fn func() error) error {
	ls.dualControlApprovalMu.Lock()
	defer ls.dualControlApprovalMu.Unlock()

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

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", int64(dualControlApprovalAdvisoryLockKey)); err != nil {
		return fmt.Errorf("failed to acquire dual-control-approval advisory lock: %w", err)
	}
	// Release before the deferred Close so the pooled connection carries no lock.
	defer func() {
		_, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", int64(dualControlApprovalAdvisoryLockKey))
	}()

	return fn()
}
