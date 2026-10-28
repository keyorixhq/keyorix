// role_set_replace.go — replacing a user's role set at one scope (SetUserRoles,
// SetProjectMemberRole) as a mixed request (INV-CORE-mixed-request-split, #3488).
//
// A replacement that removes roles AND adds others narrows access and widens it in
// one call. It is applied as two commits, each one transaction:
//
//  1. The removals, through runOwedAuditMutation: never blocked by the audit log,
//     their role.removed rows owed, settled after the auth-cache eviction and after
//     the named lock. The transaction also judges the additions' separation-of-duties
//     check against the role set it leaves, so an addition the gate refuses refuses
//     the whole request before anything commits.
//  2. The additions, fail closed (withAuditedMutation): every role.assigned row
//     commits with them, or none of them commits.
//
// Each commit re-reads the role set inside its own transaction, under the lock its
// guard needs (last-admin, project-admin, separation-of-duties), and changes only
// what that read says is still to do. If commit 2 fails after commit 1 removed
// something, the removals stay and the call returns a *PartialMutationError naming
// both halves; a retry of the same request is safe (commit 1 then removes nothing).
// Nothing re-grants a removed role: the old compensating revert (re-grant through
// AssignUserRole) failed closed on the same audit outage, lost the role, and said
// "nothing was changed" (#3488), and a re-grant after the fact can also undo a
// revocation that landed in between.
//
// One transaction for the whole replacement was rejected: it would be fail closed as
// a whole, so an audit outage would block its removals (a revocation must never be
// blocked by the audit log, Andrei 2026-10-14). The one case that IS one transaction
// is a project-admin swap that only keeps the project governed with both halves
// (SetProjectMemberRole, atomicAdminSwap): there the removals cannot stand alone.
package core

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

// errRoleSetNothingToAdd ends commit 2 when its locked re-read finds every
// addition already in place (a concurrent grant): nothing to write, no row owed.
var errRoleSetNothingToAdd = errors.New("role set: nothing left to add")

// roleSetReplace is one replacement of userID's roles at exactly scope.
type roleSetReplace struct {
	actorID, userID uint
	scope           Scope
	actorIsMachine  bool
	want            []uint // the requested set, request order, no duplicates
	// atomicAdminSwap: at project scope, when the removals alone would leave the
	// project without an administrator but the whole replacement keeps one, apply it
	// as ONE fail-closed transaction instead of refusing it.
	atomicAdminSwap bool
}

// replaceUserRoleSet applies r (file comment). Every failure before commit 1
// commits changes nothing and is returned as is.
func (c *KeyorixCore) replaceUserRoleSet(ctx context.Context, r roleSetReplace) error {
	r.want = dedupeUints(r.want)
	current, err := c.storage.GetUserRoleIDsExact(ctx, r.userID, r.scope)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	remove, add := roleSetDiff(current, r.want)
	// #3546: refuse a role the scope is invalid for BEFORE any removal, so the
	// refusal changes nothing (applyRoleSetOn writes through the tx, not through
	// grantUserRoleAudited's own check).
	for _, id := range add {
		if err := c.requireScopeValidForRole(ctx, id, r.scope); err != nil {
			return err
		}
	}
	// The grant ceiling is the actor's own authority, so it is judged before anything
	// changes; commit 2 judges it again under its lock.
	if err := c.requireGranterHoldsRoleSet(ctx, r, add); err != nil {
		return err
	}
	removed := []uint{}
	if len(remove) > 0 {
		var swapped bool
		if removed, swapped, err = c.narrowUserRoleSet(ctx, r, add); err != nil || swapped {
			return err
		}
	}
	if len(add) == 0 {
		return nil
	}
	err = c.storage.WithNamedLock(ctx, sodGrantLockKey("user", r.userID), func(ctx context.Context) error {
		if err := c.requireGranterHoldsRoleSet(ctx, r, add); err != nil {
			return err
		}
		return c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
			// NAMEDLOCK-OVERLAP-2 (txFence): the user's row first; applyRoleSetOn
			// re-reads the set and re-runs the separation-of-duties check after it.
			if err := lockUserRowsOn(ctx, tx, r.userID); err != nil {
				return err
			}
			_, err := c.applyRoleSetOn(ctx, tx, tgt, r, nil, add, true) // additions only
			return err
		})
	})
	if errors.Is(err, errRoleSetNothingToAdd) {
		return nil
	}
	if err != nil && len(removed) > 0 {
		return &PartialMutationError{
			Applied:    fmt.Sprintf("removal of role(s) %v", removed),
			NotApplied: fmt.Sprintf("addition of role(s) %v", add),
			Err:        err,
		}
	}
	return err
}

// roleSetDiff returns what replacing current with want removes and adds.
func roleSetDiff(current, want []uint) (remove, add []uint) {
	for _, id := range current {
		if !slices.Contains(want, id) {
			remove = append(remove, id)
		}
	}
	for _, id := range want {
		if !slices.Contains(current, id) {
			add = append(add, id)
		}
	}
	return remove, add
}

func (c *KeyorixCore) requireGranterHoldsRoleSet(ctx context.Context, r roleSetReplace, add []uint) error {
	for _, id := range add {
		if err := c.requireGranterHoldsRolePermissions(ctx, r.actorID, id, r.scope, r.actorIsMachine); err != nil {
			return err
		}
	}
	return nil
}

// narrowUserRoleSet is commit 1: the removals in one owed transaction under the lock
// and guard their scope needs (RemoveUserRole's), its rows settled after the
// eviction and the lock. swapped reports that the whole replacement was applied as
// one transaction instead (atomicAdminSwap).
func (c *KeyorixCore) narrowUserRoleSet(ctx context.Context, r roleSetReplace, add []uint) (removed []uint, swapped bool, err error) {
	var settle func()
	owed := func(ctx context.Context, fence txFence, removable func(id uint) bool, adminIDs []uint) error {
		var rerr error
		settle, rerr = c.runOwedAuditMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
			if err := fence(ctx, tx); err != nil {
				return err
			}
			// The additions are only judged here (assign false): they must pass the
			// separation-of-duties gate on the set this transaction leaves, or nothing is
			// removed. Commit 2 judges them again under its lock.
			var ferr error
			removed, ferr = c.applyRoleSetOn(ctx, tx, tgt, r, removable, add, false, adminIDs...)
			return ferr
		})
		return rerr
	}
	switch {
	case r.scope.ProjectID == 0 && r.scope.EnvironmentID == 0:
		// RemoveUserRole's global branch: an admin-bypass role goes through the fused
		// last-admin check, under the key and mutex every live-admin writer takes.
		var ids []uint
		if ids, err = c.adminBypassRoleIDSlice(ctx); err != nil {
			return nil, false, err // fail closed (#2496)
		}
		err = c.storage.WithNamedLock(ctx, lastAdminGuardLockKey, func(ctx context.Context) error {
			c.globalAdminGuardMu.Lock()
			defer c.globalAdminGuardMu.Unlock()
			// The global admin roles go through RemoveGlobalAdminRoleGuarded, which
			// row-locks and re-checks inside this transaction itself (safe).
			return owed(ctx, noTxFence, anyRole, ids)
		})
	case r.scope.EnvironmentID == 0:
		// withUserRoleRemovalGuards' project branch, for the whole set at once.
		err = c.storage.WithNamedLock(ctx, projectAdminGuardLockKey(r.scope.ProjectID), func(ctx context.Context) error {
			existing, gerr := c.storage.GetUserRoleIDsExact(ctx, r.userID, r.scope)
			if gerr != nil {
				return gerr
			}
			remove, _ := roleSetDiff(existing, r.want)
			after := slices.DeleteFunc(slices.Clone(existing), func(id uint) bool { return slices.Contains(remove, id) })
			gerr = c.guardLastProjectAdmin(ctx, r.scope.ProjectID, r.userID, existing, after)
			if gerr != nil && r.atomicAdminSwap &&
				c.guardLastProjectAdmin(ctx, r.scope.ProjectID, r.userID, existing, append(after, add...)) == nil {
				swapped = true
				return c.swapUserRoleSet(ctx, r, remove, add)
			}
			if gerr != nil {
				return gerr
			}
			// NAMEDLOCK-OVERLAP-2 (txFence): the same guard, on the set tx reads.
			return owed(ctx, projectAdminRemovalFence(r.scope.ProjectID, r.userID, func(existing []uint) []uint {
				remove, _ := roleSetDiff(existing, r.want)
				return slices.DeleteFunc(existing, func(id uint) bool { return slices.Contains(remove, id) })
			}), inSet(remove), nil)
		})
	default:
		// An environment-scoped grant carries no project's roles.assign authority.
		err = owed(ctx, noTxFence, anyRole, nil)
	}
	if err != nil {
		return nil, swapped, err
	}
	if len(removed) > 0 {
		c.evictUserSessionCache(ctx, r.userID)
	}
	if settle != nil {
		settle() // after the eviction and the lock (INV-CORE-mixed-request-split)
	}
	return removed, swapped, nil
}

// swapUserRoleSet applies the removals and the additions in ONE fail-closed
// transaction, under the project-admin lock its caller holds and the grant lock: the
// removals alone would leave the project without an administrator, so they cannot
// commit without the additions. During an audit outage nothing changes.
func (c *KeyorixCore) swapUserRoleSet(ctx context.Context, r roleSetReplace, remove, add []uint) error {
	var removed []uint
	err := c.storage.WithNamedLock(ctx, sodGrantLockKey("user", r.userID), func(ctx context.Context) error {
		if err := c.requireGranterHoldsRoleSet(ctx, r, add); err != nil {
			return err
		}
		return c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
			// NAMEDLOCK-OVERLAP-2 (txFence): the project's key and the swap's own
			// last-admin verdict (the removals AND the additions) through tx, then
			// the user's row for the separation-of-duties re-check.
			if err := projectAdminRemovalFence(r.scope.ProjectID, r.userID, func(existing []uint) []uint {
				after := slices.DeleteFunc(existing, func(id uint) bool { return slices.Contains(remove, id) })
				return append(after, add...)
			})(ctx, tx); err != nil {
				return err
			}
			if err := lockUserRowsOn(ctx, tx, r.userID); err != nil {
				return err
			}
			var err error
			removed, err = c.applyRoleSetOn(ctx, tx, tgt, r, inSet(remove), add, true)
			return err
		})
	})
	if errors.Is(err, errRoleSetNothingToAdd) {
		return nil
	}
	if err == nil && len(removed) > 0 {
		c.evictUserSessionCache(ctx, r.userID)
	}
	return err
}

// anyRole and inSet say which roles applyRoleSetOn may remove.
func anyRole(uint) bool { return true }

func inSet(ids []uint) func(uint) bool {
	return func(id uint) bool { return slices.Contains(ids, id) }
}

// applyRoleSetOn re-reads the role set in tx and applies, against that read, the
// removals r.want calls for that removable allows (nil: none; a guarded caller passes
// the set its guard approved) and the additions in add not already held (assign
// false: only judged by the separation-of-duties gate, on the set the removals
// leave), then writes their audit rows through tgt, last. adminIDs are the global
// admin-bypass roles, removed through the fused last-admin check. It returns the roles
// it removed; an assigning call that finds nothing left to do returns
// errRoleSetNothingToAdd.
func (c *KeyorixCore) applyRoleSetOn(ctx context.Context, tx storage.Storage, tgt auditTarget, r roleSetReplace, removable func(id uint) bool, add []uint, assign bool, adminIDs ...uint) (removed []uint, err error) {
	current, err := tx.GetUserRoleIDsExact(ctx, r.userID, r.scope)
	if err != nil {
		return nil, err
	}
	remove, _ := roleSetDiff(current, r.want)
	for _, id := range remove {
		if removable == nil || !removable(id) {
			continue // not this commit's, or not approved by the caller's guard
		}
		if slices.Contains(adminIDs, id) {
			err = tx.RemoveGlobalAdminRoleGuarded(ctx, r.userID, id, adminIDs)
		} else {
			err = tx.RemoveRole(ctx, r.userID, id, r.scope)
		}
		if errors.Is(err, storage.ErrRoleNotAssigned) {
			continue // removed concurrently (e.g. an expiry sweep): nothing to record
		}
		if err != nil {
			return nil, err
		}
		removed = append(removed, id)
	}
	var added []uint
	for _, id := range add {
		if !slices.Contains(current, id) {
			added = append(added, id)
		}
	}
	if assign && len(added) == 0 && len(removed) == 0 {
		return nil, errRoleSetNothingToAdd
	}
	if len(added) > 0 {
		if err := requireNoSoDViolationOn(ctx, tx, r.userID, added, r.scope); err != nil {
			return nil, err
		}
	}
	if !assign {
		added = nil
	}
	for _, id := range added {
		if err := tx.AssignRole(ctx, r.userID, id, r.scope); err != nil {
			return nil, err
		}
	}
	for _, id := range removed {
		c.LogRoleRemovedOn(ctx, tgt, r.actorID, r.userID, id, r.scope)
	}
	for _, id := range added {
		c.LogRoleAssignedOn(ctx, tgt, r.actorID, r.userID, id, r.scope)
	}
	return removed, nil
}
