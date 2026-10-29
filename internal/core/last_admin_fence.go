package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// fenceLastAdminDeactivationOn is the in-transaction half of the last-admin
// guard for a user deactivation (NAMEDLOCK-OVERLAP-1). It must be the first
// thing the deactivating write transaction does, before it row-locks the target.
//
// lastAdminGuardLockKey alone does not keep the invariant: when its advisory
// lock's connection dies, a second replica can take the key up to one ping
// interval plus the ping timeout before the first holder's ctx is cancelled
// (docs/design/pooler-lock-loss.md, "The overlap window"). Two deactivations of
// two different admins that overlap there each passed guardLastAdminDeactivation
// before the other committed, and both commit: no admin is left.
//
// The fence closes that without the named lock: it row-locks every global
// admin-tier grant (ListGlobalAdminAssignmentsForUpdate, FOR UPDATE on
// PostgreSQL) and re-runs the guard through tx. Every write transaction that can
// remove the last admin locks the same rows, so on PostgreSQL the second waits
// for the first to commit, and its re-check (later statements, a fresh READ
// COMMITTED snapshot) sees the first one's deactivation and refuses.
// RemoveGlobalAdminRoleGuarded takes the same rows in the same order (grants,
// then users), so the two cannot deadlock. On SQLite there is no overlap
// window (the named lock is an in-process mutex and every transaction is
// BEGIN IMMEDIATE), and the re-check runs on the committed state.
//
// The guard before the transaction stays: it is the cheap refusal that runs
// without a row lock, and the error a caller sees in the ordinary case.
//
// A target that holds no admin-tier role cannot be the last admin, so its
// deactivation takes no grant row lock (the guard itself returns early for it):
// only deactivations of admins serialize on these rows.
func fenceLastAdminDeactivationOn(ctx context.Context, tx storage.Storage, targetID uint) error {
	isAdmin, err := targetHasGlobalAdminRoleOn(ctx, tx, targetID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err) // fail closed (#337)
	}
	if !isAdmin {
		return nil
	}
	if err := lockGlobalAdminGrantsOn(ctx, tx); err != nil {
		return err
	}
	return guardLastAdminDeactivationOn(ctx, tx, targetID)
}

// lockGlobalAdminGrantsOn row-locks every global admin-tier grant in tx, the
// rows every last-admin verdict rests on (see fenceLastAdminDeactivationOn).
// With no admin-bypass role seeded there is nothing to lock or to strand.
func lockGlobalAdminGrantsOn(ctx context.Context, tx storage.Storage) error {
	ids, err := tx.ListAdminBypassRoleIDs(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if _, err := tx.ListGlobalAdminAssignmentsForUpdate(ctx, ids); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return nil
}
