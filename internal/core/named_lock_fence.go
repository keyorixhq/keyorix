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

// lockUserRowsOn row-locks each user in ids (LockUserForUpdate), in ascending
// ID order: the row every separation-of-duties fence for that user takes, so
// two grants that change the same user's permissions serialize. A user with no
// live row (deleted, soft-deleted) has nothing to lock and is skipped; the
// caller's re-check still runs.
func lockUserRowsOn(ctx context.Context, tx storage.Storage, ids ...uint) error {
	sorted := slices.Clone(ids)
	slices.Sort(sorted)
	for _, id := range slices.Compact(sorted) {
		if _, err := tx.LockUserForUpdate(ctx, id); err != nil && !storage.IsUserNotFound(err) {
			return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
	}
	return nil
}

// sodUserGrantFence is the fence of a direct grant of roleIDs to userID at
// scope: it row-locks the user, then re-runs requireNoSoDViolationOn through
// tx with the inputs the grant's own check used. Every writer that can add to
// a user's permissions under sodGrantLockKey("user", ...) takes the same row:
// the direct grants, a group join (AddUserToGroup), a role-set replacement,
// and a group grant for each member (sodGroupGrantFence).
func sodUserGrantFence(userID uint, roleIDs []uint, scope Scope) txFence {
	return func(ctx context.Context, tx storage.Storage) error {
		if err := lockUserRowsOn(ctx, tx, userID); err != nil {
			return err
		}
		return requireNoSoDViolationOn(ctx, tx, userID, roleIDs, scope)
	}
}
