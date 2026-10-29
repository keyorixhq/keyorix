package core

import (
	"context"
	"fmt"
	"slices"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
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

// chainTxFences runs fences in order, stopping at the first error. The caller
// orders them by the lock order above (named keys before rows).
func chainTxFences(fences ...txFence) txFence {
	return func(ctx context.Context, tx storage.Storage) error {
		for _, f := range fences {
			if err := f(ctx, tx); err != nil {
				return err
			}
		}
		return nil
	}
}

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

// sodGroupGrantFence is the fence of a grant of roleID to a group whose
// members withGroupMemberSoDLocks snapshotted (and named-locked, in ascending
// ID order): it row-locks every active member's user row in the same order,
// then re-runs the group grant's separation-of-duties check through tx on that
// same snapshot. A direct grant to a member, or another group grant reaching
// one, locks that member's row too (sodUserGrantFence, this fence), so the two
// transactions serialize and the later one's check sees the earlier one's
// grant.
func sodGroupGrantFence(roleID uint, members []*models.User) txFence {
	ids := make([]uint, 0, len(members))
	for _, m := range members {
		if m.IsActive {
			ids = append(ids, m.ID)
		}
	}
	return func(ctx context.Context, tx storage.Storage) error {
		if err := lockUserRowsOn(ctx, tx, ids...); err != nil {
			return err
		}
		policies, adding, needed, err := groupGrantSoDContextOn(ctx, tx, roleID)
		if err != nil || !needed {
			return err
		}
		return requireGroupGrantNoSoDViolationOn(ctx, tx, members, policies, adding)
	}
}

// projectAdminRemovalFence is the fence of a write that removes some of
// userID's roles at projectID's project scope: projectAdminGuardLockKey with
// LockNamedKeyInTx (every writer of the project's last-admin invariant takes
// it in its write transaction, the group paths included:
// withGroupProjectAdminGuardLocks, withGroupRoleRemovalGuards), then
// guardLastProjectAdmin through tx, on the user's project-level roles as tx
// reads them once the key is held and on what after says the write leaves of
// them.
func projectAdminRemovalFence(projectID, userID uint, after func(existing []uint) []uint) txFence {
	return func(ctx context.Context, tx storage.Storage) error {
		if err := lockNamedKeysInTxOn(ctx, tx, projectAdminGuardLockKey(projectID)); err != nil {
			return err
		}
		existing, err := tx.GetUserRoleIDsExact(ctx, userID, Scope{ProjectID: projectID})
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		return guardLastProjectAdminOn(ctx, tx, projectID, userID, existing, after(slices.Clone(existing)))
	}
}

// withoutRole returns an after function for projectAdminRemovalFence: the
// existing roles minus roleID.
func withoutRole(roleID uint) func(existing []uint) []uint {
	return func(existing []uint) []uint {
		return slices.DeleteFunc(existing, func(id uint) bool { return id == roleID })
	}
}

// sodGroupKeyFence takes sodGrantLockKey("group", groupID) with
// LockNamedKeyInTx: the key a grant to the group holds, taken again inside its
// write transaction so RestoreGroup's transaction (which takes it too, then
// re-reads the group's roles for its ceiling check) and the grant serialize
// even when one side's named lock was lost. First in the transaction: the
// group key ranks before the members' rows (sodGroupGrantFence).
func sodGroupKeyFence(groupID uint) txFence {
	return func(ctx context.Context, tx storage.Storage) error {
		return lockNamedKeysInTxOn(ctx, tx, sodGrantLockKey("group", groupID))
	}
}
