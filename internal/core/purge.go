// purge.go — retention purge of soft-deleted records (ADR-032).
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// PurgeResult reports how many soft-deleted rows each entity purge removed.
type PurgeResult struct {
	Users        int64 `json:"users"`
	Projects     int64 `json:"projects"`
	Environments int64 `json:"environments"`
	Secrets      int64 `json:"secrets"`
}

// Total is the combined count of purged rows.
func (r PurgeResult) Total() int64 {
	return r.Users + r.Projects + r.Environments + r.Secrets
}

// PurgeExpiredSoftDeletes hard-deletes every soft-deleted user, project, and
// environment whose deleted_at predates `before`. Each top-level entity is purged
// independently on its own deleted_at; a purged secret additionally cascades to its
// ciphertext-bearing version rows (which carry no deleted_at of their own), so the
// secret value is truly destroyed and not left recoverable. When anything was removed
// it emits one system-actored `data.purged` audit event with the counts. Errors on
// individual entities are collected but do not abort the others.
func (c *KeyorixCore) PurgeExpiredSoftDeletes(ctx context.Context, before time.Time) (*PurgeResult, error) {
	// #G21: the legal-hold check and all four deletes below run inside ONE
	// transaction — previously the guard was checked once, then four SEPARATE,
	// unsynchronized delete calls followed, leaving a window across all four
	// where PlaceLegalHold could commit in between (irreversible spoliation,
	// ISO A.5.34). SQLite's single-writer model means this transaction holds an
	// exclusive write lock for its whole duration, so a concurrent
	// PlaceLegalHold's INSERT cannot land partway through. Each Purge*Before
	// call already manages its own internal atomicity (a nested
	// transaction/savepoint), so a single entity's failure doesn't abort the
	// others — matching the pre-existing "continue past individual errors,
	// report the first" partial-success design. NOTE: RemoteStorage.WithTransaction
	// is a no-op passthrough — under storage.type: remote this narrows the
	// window but does not eliminate it (see audit_retention.go's PurgeAuditLogs
	// for the same caveat).
	res := &PurgeResult{}
	var firstErr error
	record := func(n int64, err error) int64 {
		if err != nil && firstErr == nil {
			firstErr = err
		}
		return n
	}

	txErr := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		hold, err := tx.GetActiveLegalHold(ctx)
		if err != nil {
			return fmt.Errorf("refusing to purge: could not confirm legal-hold status: %w", err)
		}
		if hold != nil {
			return fmt.Errorf("refusing to purge: a deployment-wide legal hold is active")
		}
		res.Users = record(tx.PurgeDeletedUsersBefore(ctx, before))
		res.Projects = record(tx.PurgeDeletedProjectsBefore(ctx, before))
		res.Environments = record(tx.PurgeDeletedEnvironmentsBefore(ctx, before))
		res.Secrets = record(tx.PurgeDeletedSecretsBefore(ctx, before))
		return nil
	})
	if txErr != nil {
		return &PurgeResult{}, txErr
	}

	if res.Total() > 0 {
		sysCtx := WithActorType(ctx, ActorTypeSystem)
		c.writeAuditEvent(sysCtx, "data.purged", nil, nil,
			fmt.Sprintf("retention purge removed %d soft-deleted records (users=%d, projects=%d, environments=%d, secrets=%d) older than %s",
				res.Total(), res.Users, res.Projects, res.Environments, res.Secrets, before.UTC().Format(time.RFC3339)))
	}

	return res, firstErr
}
