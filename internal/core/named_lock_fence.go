package core

import (
	"context"
	"fmt"
	"slices"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// txFence is the in-transaction half of a WithNamedLock section
// (NAMEDLOCK-OVERLAP-2, docs/design/named-lock-overlap.md). A section's named
// lock serializes its checks across replicas only while the lock's connection
// lives: when it dies, a second replica can take the key and run the same
// section before the first holder's ctx is cancelled. The fence keeps the
// invariant anyway. Run as the FIRST statement of the section's write
// transaction, it takes locks that every competing writer's transaction also
// takes, then re-runs the section's own check through tx: the second writer's
// transaction waits for the first one's to end, and its re-check (later
// statements, a fresh READ COMMITTED snapshot) sees the first one's write.
//
// A fence never adds a refusal: it re-runs the check the section already ran
// before its transaction, on the same inputs, against the state as committed
// when the locks were granted.
//
// Lock order inside a transaction, the same for every fence so two fenced
// transactions cannot wait on each other in a cycle: named keys first
// (LockNamedKeyInTx, in storage.NamedLockOrder), then rows: global admin-tier
// grant rows, then user rows in ascending ID. #3753's fenceLastAdminDeactivationOn
// and RemoveGlobalAdminRoleGuarded already take grant rows before user rows.
type txFence func(ctx context.Context, tx storage.Storage) error

// noTxFence is the fence of a removal that needs none (an environment-scoped
// grant, which carries no project's roles.assign authority).
func noTxFence(context.Context, storage.Storage) error { return nil }

// lockNamedKeysInTxOn takes every key with tx.LockNamedKeyInTx, in the order
// given, and refuses (taking nothing more) an order storage.NamedLockOrder does
// not allow: two transactions taking the same keys in opposite orders would
// wait on each other for good.
func lockNamedKeysInTxOn(ctx context.Context, tx storage.Storage, keys ...string) error {
	for i, key := range keys {
		if err := storage.CheckNamedLockOrder(keys[:i], key); err != nil {
			return err
		}
		if err := tx.LockNamedKeyInTx(ctx, key); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
	}
	return nil
}

// projectAdminGuardKeys returns projectAdminGuardLockKey for each project, in
// ascending ID order (the order lockProjectAdminGuardsInOrder takes them).
func projectAdminGuardKeys(projectIDs ...uint) []string {
	ids := slices.Clone(projectIDs)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	keys := make([]string, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, projectAdminGuardLockKey(id))
	}
	return keys
}
