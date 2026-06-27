// purge.go — retention purge of soft-deleted records (ADR-032).
package core

import (
	"context"
	"fmt"
	"time"
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
	// Re-check the legal hold HERE — inside the purge, under the scheduler lock and
	// immediately before the deletes — not only in the scheduler closure before the lock
	// is taken. Otherwise a hold placed after the pre-lock check (PlaceLegalHold doesn't
	// take the lock) would not stop an in-flight purge from hard-deleting records that are
	// now under hold (irreversible spoliation, ISO A.5.34). Fails SAFE: an unconfirmable
	// hold status aborts the purge.
	if err := c.legalHoldGuard(ctx); err != nil {
		return &PurgeResult{}, err
	}
	res := &PurgeResult{}
	var firstErr error
	record := func(n int64, err error) int64 {
		if err != nil && firstErr == nil {
			firstErr = err
		}
		return n
	}

	res.Users = record(c.storage.PurgeDeletedUsersBefore(ctx, before))
	res.Projects = record(c.storage.PurgeDeletedProjectsBefore(ctx, before))
	res.Environments = record(c.storage.PurgeDeletedEnvironmentsBefore(ctx, before))
	res.Secrets = record(c.storage.PurgeDeletedSecretsBefore(ctx, before))

	if res.Total() > 0 {
		sysCtx := WithActorType(ctx, ActorTypeSystem)
		c.writeAuditEvent(sysCtx, "data.purged", nil, nil,
			fmt.Sprintf("retention purge removed %d soft-deleted records (users=%d, projects=%d, environments=%d, secrets=%d) older than %s",
				res.Total(), res.Users, res.Projects, res.Environments, res.Secrets, before.UTC().Format(time.RFC3339)))
	}

	return res, firstErr
}
