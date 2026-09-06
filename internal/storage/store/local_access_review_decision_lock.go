// local_access_review_decision_lock.go — serializes DecideAccessReviewItem's
// pending-check + attest/revoke action + decision-stamp sequence across
// replicas (#419/#G04-HA).
//
// persistItemDecision's conditional UPDATE already stops a SECOND writer from
// persisting its Decision stamp, but that alone does not stop a second
// concurrent caller from executing the real attest/revoke ACTION before
// either write commits: without a lock spanning the whole sequence, two
// replicas racing the same pending item can each read Decision==pending and
// each carry out its side effect (e.g. an actual revoke), even though only
// the winner's stamp survives — leaving the persisted evidence silently
// wrong about what was decided.
package store

import (
	"context"
	"fmt"
)

// accessReviewDecisionAdvisoryLockKey is the Postgres advisory-lock key
// guarding DecideAccessReviewItem's check-act-persist sequence across
// processes. Distinct from every other advisory-lock key in this package.
const accessReviewDecisionAdvisoryLockKey = 0x4B455941_4152444C // "KEYAARDL"

// WithAccessReviewDecisionLock runs fn with DecideAccessReviewItem's
// pending-check-through-persist sequence serialized: a process-level mutex
// covers the common single-writer self-host topology and SQLite (inherently
// single-instance — there is no DB-level advisory lock to take); a
// PostgreSQL session-scoped advisory lock (pg_advisory_lock) extends that
// across processes/replicas (ADR-039 HA).
//
// Like WithBootstrapLock/WithAuditCheckpointLock, this BLOCKS until the lock
// is acquired rather than skipping on contention — a replica that loses the
// race must actually re-run its pending check under the lock and observe the
// winner's now-committed decision, not silently no-op.
func (ls *LocalStorage) WithAccessReviewDecisionLock(ctx context.Context, fn func() error) error {
	ls.accessReviewDecisionMu.Lock()
	defer ls.accessReviewDecisionMu.Unlock()

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

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", int64(accessReviewDecisionAdvisoryLockKey)); err != nil {
		return fmt.Errorf("failed to acquire access-review-decision advisory lock: %w", err)
	}
	// Release before the deferred Close so the pooled connection carries no lock.
	defer func() {
		_, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", int64(accessReviewDecisionAdvisoryLockKey))
	}()

	return fn()
}
