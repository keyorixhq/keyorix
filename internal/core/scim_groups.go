// scim_groups.go — SCIM 2.0 group sync (RFC 7644), the companion to scim.go. An IdP
// creates groups and pushes their membership; Keyorix maps a SCIM Group to a native
// Group (displayName → Name) and its members to user↔group links. PUT replaces the
// full member set; PATCH adds/removes members (and may rename). All mutations are
// audited.
package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"slices"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	EventSCIMGroupProvisioned   = "scim.group_provisioned"
	EventSCIMGroupUpdated       = "scim.group_updated"
	EventSCIMGroupDeprovisioned = "scim.group_deprovisioned"
)

// ListSCIMGroupsPage returns one page of groups for a SCIM list and the total
// count, mirroring ListSCIMUsersPage (scim.go): startIndex is 1-based (SCIM
// convention), count is clamped to [0, SCIMMaxPageSize]. Unlike ListGroups (used
// by SSO group sync and other callers that intentionally want every group),
// this is backed by a bounded, offset-limited storage query so an unfiltered SCIM
// directory sync can't load the whole groups table into memory.
func (c *KeyorixCore) ListSCIMGroupsPage(ctx context.Context, startIndex, count int) ([]*models.Group, int, error) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 0 {
		count = 0
	}
	if count > SCIMMaxPageSize {
		count = SCIMMaxPageSize
	}
	if count == 0 {
		// SCIM count=0 → return totalResults only. Use PageSize=1 to get an accurate
		// total without a separate count API; the single fetched row is discarded.
		// (Requesting PageSize=0 directly is not relied on here: GORM's Limit(0)
		// semantics are not "zero rows" across all backends, so ListSCIMUsersPage
		// avoids it too — mirrored here for the same reason.)
		_, total, err := c.storage.ListGroupsPage(ctx, 0, 1)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		return []*models.Group{}, int(total), nil
	}
	groups, total, err := c.storage.ListGroupsPage(ctx, startIndex-1, count)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return groups, int(total), nil
}

// scimManagedMember reports whether uid identifies a SCIM-owned account (scimOwned: a
// stored externalId set by SCIM user-provisioning — not empty like a native/local
// account, not the SSO scheme like an account SSO claimed or JIT-provisioned, #3418).
// SCIM group membership mutations (Create/Replace/PATCH) must refuse any
// target that isn't: those endpoints take arbitrary numeric member ids straight off
// the SCIM payload with no check that the id belongs to an account SCIM actually owns,
// so a valid (e.g. group-provisioning-only) SCIM bearer token could otherwise add ANY
// native user — including one the attacker already controls — into a group. If that
// group carries an admin-conferring role (a common "IdP group X = Keyorix admins"
// integration pattern), membership alone grants the role immediately, with no SSO
// step required (#167 — the group-membership sibling of #120's user-level guard).
// Fails CLOSED: a user that positively does not exist is not managed (false, nil), and
// an inability to verify returns the error, so the add never opens, and the caller
// answers a server error the IdP retries rather than a refusal it would not (#3620).
func (c *KeyorixCore) scimManagedMember(ctx context.Context, uid uint) (bool, error) {
	user, err := c.storage.GetUser(ctx, uid)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return false, nil
		}
		return false, err
	}
	return scimOwned(user), nil
}

// maxSCIMGroupMembersPerCall bounds how many member ids a single SCIM group
// provision/replace/patch request may carry. Each id costs one
// scimManagedMember (GetUser) round trip via filterSCIMManaged below; an IdP
// integration (or a compromised/misbehaving one) submitting an unbounded
// member list in one request is a per-request resource-exhaustion vector, the
// same class of bug as maxBulkAccessRequestBatchSize
// (internal/core/bulk_access_requests.go). Enforced at each of the three SCIM
// group entry points (ProvisionSCIMGroup, ReplaceSCIMGroup, PatchSCIMGroup)
// against their raw incoming id list, before any storage access.
const maxSCIMGroupMembersPerCall = 500

// filterSCIMManaged splits ids into (allowed, rejected) member ids based on
// scimManagedMember, so callers can add only the SCIM-managed subset and report the
// rest as refused rather than silently dropping them. A failed lookup is returned as
// an error, not counted as a rejection.
func (c *KeyorixCore) filterSCIMManaged(ctx context.Context, ids []uint) (allowed, rejected []uint, err error) { // nosemgrep: keyorix-unbounded-bulk-slice-param -- all three callers (ProvisionSCIMGroup, ReplaceSCIMGroup, PatchSCIMGroup) enforce maxSCIMGroupMembersPerCall on their raw incoming id list before calling this
	for _, id := range ids {
		if id == 0 {
			continue
		}
		managed, merr := c.scimManagedMember(ctx, id)
		if merr != nil {
			return nil, nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), merr)
		}
		if managed {
			allowed = append(allowed, id)
		} else {
			rejected = append(rejected, id)
		}
	}
	return allowed, rejected, nil
}

// scimMembersRefused is the refusal for member ids the group sync may not add.
func scimMembersRefused(rejected []uint) error {
	return fmt.Errorf("%s: %w (rejected member id(s): %v)", i18n.T("ErrorNotAuthorized", nil), ErrSCIMMemberNotManaged, rejected)
}

// SCIMGroupState is a SCIM group as its own write left it: the group row and its
// members. The SCIM response needs both, and a read after the commit (GetGroup, then
// the handler's member list) that fails would report a write that already committed as
// failed, which an IdP answers by retrying or by resyncing from a state it thinks did
// not change (SCIM-GROUPS-ERR-1). A write that can widen access (a create, an add, a
// rename) reads it INSIDE its transaction, so for a single-commit write a failed read
// rolls the write back and the error is a true "not applied". Two exceptions:
//   - A pure member removal is a revocation (owed audit, AUDIT-TX-3) and nothing
//     non-essential may roll it back, so it reads after its commit; a failed read there
//     is ErrSCIMGroupStateUnavailable, the removal applied.
//   - In a split request (MERGE-FIX-3482G) the removals commit first and stand; a failed
//     read in commit 2 rolls back only the adds/rename (PartialMutationError).
type SCIMGroupState struct {
	*models.Group
	Members []*models.User
}

// readSCIMGroupState reads groupID and its members through tx. Errors keep their
// storage typing (a missing group stays storage.ErrGroupNotFound).
func (c *KeyorixCore) readSCIMGroupState(ctx context.Context, tx storage.Storage, groupID uint) (*SCIMGroupState, error) {
	g, err := tx.GetGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	members, err := tx.ListGroupMembers(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &SCIMGroupState{Group: g, Members: members}, nil
}

// readBackAfterRevocation runs read, the response's read-back after a pure member
// removal committed (outside its transaction, see SCIMGroupState). A failure, a panic
// included, is ErrSCIMGroupStateUnavailable wrapping the cause: the removal stands.
func readBackAfterRevocation(read func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SCIM group read-back panicked after a member removal committed (the removal stands): %v\n%s", r, debug.Stack())
			err = fmt.Errorf("%w: the read-back panicked: %v", ErrSCIMGroupStateUnavailable, r)
		}
	}()
	if rerr := read(); rerr != nil {
		return fmt.Errorf("%w: %w", ErrSCIMGroupStateUnavailable, rerr)
	}
	return nil
}

// ProvisionSCIMGroup creates a group from a SCIM Create and adds its initial members.
// Only SCIM-managed members may be added (scimManagedMember, #167); a non-SCIM-managed
// id in memberIDs is refused.
func (c *KeyorixCore) ProvisionSCIMGroup(ctx context.Context, actorID uint, displayName string, memberIDs []uint) (*SCIMGroupState, error) {
	if displayName == "" {
		return nil, fmt.Errorf("%w: displayName is required", ErrInvalidInput)
	}
	if len(memberIDs) > maxSCIMGroupMembersPerCall {
		return nil, fmt.Errorf("%w: memberIDs exceeds the maximum batch size of %d", ErrInvalidInput, maxSCIMGroupMembersPerCall)
	}
	allowed, rejected, ferr := c.filterSCIMManaged(ctx, memberIDs)
	if ferr != nil {
		return nil, ferr
	}
	if len(rejected) > 0 {
		return nil, scimMembersRefused(rejected)
	}
	// #1642: SCIM-provisioned group names come from an external IdP and
	// bypass core.CreateGroup entirely (see the storage-direct note below),
	// so they need their own fold — mirrors ProvisionSCIMUser's identical
	// treatment (scim.go).
	foldedName, ferr := identity.NewFoldedName(displayName)
	if ferr != nil {
		return nil, fmt.Errorf("%s: %w: %w", i18n.T("ErrorValidation", nil), ErrInvalidInput, ferr)
	}
	// Storage-direct: the SCIM path emits its own scim.group_provisioned event below,
	// so it must not also fire the generic group.created from CreateGroup.
	//
	// The group row and its initial membership run in one transaction: a partial
	// membership apply used to be best-effort (`_ =`), and — since a POST is not
	// retry-safe the way PATCH is — a failed member add on a create previously left
	// a partially-populated group with no signal to the IdP that anything was wrong
	// (the create itself reported success), and a retry would create a SECOND,
	// duplicate group rather than complete the first one. AddUserToGroup is
	// idempotent (a second add to the same (user, group, 0) is a no-op), so this is
	// also safe to retry once the whole create is atomic.
	//
	// AUDIT-TX-3: a group created with members confers whatever roles it later holds
	// to them, so the scim.group_provisioned row commits with the group or not at all.
	//
	// The state the response renders is read in the same transaction (SCIMGroupState).
	var state *SCIMGroupState
	err := c.withAuditedMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
		group, cerr := tx.CreateGroup(ctx, &models.Group{Name: displayName, NameFolded: foldedName.Folded()})
		if cerr != nil {
			return cerr
		}
		for _, uid := range allowed {
			if aerr := tx.AddUserToGroup(ctx, uid, group.ID, 0); aerr != nil { // SCIM memberships are always global
				return aerr
			}
		}
		c.writeAuditEventFullOn(ctx, tgt, EventSCIMGroupProvisioned, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("SCIM provisioned group %d (%q) with %d member(s)", group.ID, displayName, len(allowed)))
		state, cerr = c.readSCIMGroupState(ctx, tx, group.ID)
		return cerr
	})
	if err != nil {
		return nil, err
	}
	return state, nil
}

// ReplaceSCIMGroup applies a SCIM Replace (PUT): an optional rename plus the FULL
// member set (members not in memberIDs are removed; new ones are added).
func (c *KeyorixCore) ReplaceSCIMGroup(ctx context.Context, actorID, groupID uint, displayName string, memberIDs []uint) (*SCIMGroupState, error) {
	if len(memberIDs) > maxSCIMGroupMembersPerCall {
		return nil, fmt.Errorf("%w: memberIDs exceeds the maximum batch size of %d", ErrInvalidInput, maxSCIMGroupMembersPerCall)
	}
	group, err := c.storage.GetGroup(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	var rename func(tx storage.Storage) error
	if displayName != "" && displayName != group.Name {
		// #1642: keep NameFolded in lockstep with Name on every rename path,
		// not just core.UpdateGroup's — a stale NameFolded here would leave
		// the DB's uniqueness index checking a value that no longer matches
		// the group's actual display name.
		foldedName, ferr := identity.NewFoldedName(displayName)
		if ferr != nil {
			return nil, fmt.Errorf("%s: %w: %w", i18n.T("ErrorValidation", nil), ErrInvalidInput, ferr)
		}
		// #2697: column-scoped, conditional on the group row still being live —
		// a full-row Save here resurrected a group a concurrent
		// DeprovisionSCIMGroup/DeleteGroup had just removed, bringing its
		// retained role grants and memberships back with it. An IdP DELETE
		// followed closely by a PUT/PATCH is exactly this interleaving.
		//
		// AUDIT-TX-3: the rename runs in the same transaction as the membership
		// change and its audit row (applyGroupMembershipChanges), so a failure there
		// no longer leaves the rename committed on its own.
		folded := foldedName.Folded()
		rename = func(tx storage.Storage) error {
			matched, uerr := tx.UpdateGroupFields(ctx, groupID, &displayName, &folded, nil, c.now())
			if uerr != nil {
				return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), uerr)
			}
			if !matched {
				return fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), storage.ErrGroupNotFound)
			}
			return nil
		}
	}
	current, err := c.storage.ListGroupMembers(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	want, have := buildSCIMMemberMaps(memberIDs, current)
	toAdd := computeSCIMToAdd(want, have)
	// SCIM must not be able to grant administrative access by adding members to a group
	// that carries an admin role. Block the add (de-escalating removals are still fine).
	if len(toAdd) > 0 {
		if err := c.refuseAddToAdminGroup(ctx, groupID); err != nil {
			return nil, err
		}
	}
	// Every add must target a SCIM-managed account (#167); a native/non-SCIM id in the
	// requested member set is refused outright rather than silently skipped.
	if _, rejected, ferr := c.filterSCIMManaged(ctx, toAdd); ferr != nil {
		return nil, ferr
	} else if len(rejected) > 0 {
		return nil, scimMembersRefused(rejected)
	}
	var state *SCIMGroupState
	if err := c.applyGroupMembershipChanges(ctx, groupID, want, current, toAdd, rename, func(tgt auditTarget) {
		c.writeAuditEventFullOn(ctx, tgt, EventSCIMGroupUpdated, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("SCIM replaced group %d: removed the members not in the new set", groupID))
	}, func(tgt auditTarget) {
		c.writeAuditEventFullOn(ctx, tgt, EventSCIMGroupUpdated, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("SCIM replaced group %d (members=%d)", groupID, len(want)))
	}, func(tx storage.Storage) (rerr error) {
		state, rerr = c.readSCIMGroupState(ctx, tx, groupID)
		return rerr
	}); err != nil {
		return nil, err
	}
	return state, nil
}

// PatchSCIMGroup applies a SCIM PATCH: an optional rename plus incremental member
// add/remove. nil newName leaves the name unchanged.
func (c *KeyorixCore) PatchSCIMGroup(ctx context.Context, actorID, groupID uint, newName *string, addIDs, removeIDs []uint) (*SCIMGroupState, error) {
	if len(addIDs) > maxSCIMGroupMembersPerCall || len(removeIDs) > maxSCIMGroupMembersPerCall {
		return nil, fmt.Errorf("%w: addIDs/removeIDs exceeds the maximum batch size of %d", ErrInvalidInput, maxSCIMGroupMembersPerCall)
	}
	group, err := c.storage.GetGroup(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	renaming := false
	var folded string
	if newName != nil && *newName != "" && *newName != group.Name {
		foldedName, ferr := identity.NewFoldedName(*newName)
		if ferr != nil {
			return nil, fmt.Errorf("%s: %w: %w", i18n.T("ErrorValidation", nil), ErrInvalidInput, ferr)
		}
		// #2697: see ReplaceSCIMGroup's identical rename above (AUDIT-TX-3: it runs
		// in the membership transaction below).
		renaming, folded = true, foldedName.Folded()
	}
	if hasSCIMAdditions(addIDs) {
		if err := c.refuseAddToAdminGroup(ctx, groupID); err != nil {
			return nil, err
		}
	}
	// Every add must target a SCIM-managed account (#167); a native/non-SCIM id in the
	// requested add set is refused outright rather than silently skipped.
	allowedAdds, rejected, ferr := c.filterSCIMManaged(ctx, addIDs)
	if ferr != nil {
		return nil, ferr
	}
	if len(rejected) > 0 {
		return nil, scimMembersRefused(rejected)
	}
	// SESSION-AT #2352: guard checks + the write both now run under
	// withGroupProjectAdminGuardLocks (global key + every project key this
	// group holds roles.assign at). An earlier version ran these guard checks
	// with no lock at all, before the transaction below — two concurrent
	// membership changes (another SCIM PATCH/PUT, or a native RemoveUserFromGroup)
	// could each observe "another admin survives" before either commits.
	toRemove := filterNonZero(removeIDs)
	// An id in both lists ends removed: the single transaction used to apply the adds
	// first and the removals last. The split applies the removals first, so such an
	// add is dropped here; it neither widens nor re-adds the member in commit 2.
	allowedAdds = slices.DeleteFunc(allowedAdds, func(id uint) bool { return slices.Contains(toRemove, id) })
	widens := len(allowedAdds) > 0 || renaming
	// split: removals that really remove a member, plus an add or a rename, make a
	// mixed request (MERGE-FIX-3482G): the removals commit alone (owed) under the
	// guard locks, and the adds/rename follow as their own fail-closed commit.
	var split bool
	var settle func()
	var state *SCIMGroupState // the group as the last commit left it (readSCIMGroupState)
	// Check every removal against guardLastGlobalAdminMembership (#G02) BEFORE
	// applying any of them, so a PATCH that would strip the install's last route
	// to global-admin authority is refused atomically — see
	// applyGroupMembershipChanges's identical precheck-then-apply shape. Also
	// checked against guardLastProjectAdminGroupMembership (core-project-
	// members.json#3) so a removal can't strip a project's last roles.assign
	// holder either — SCIM group management previously only saw the global case.
	guard := scimRemovalsGuard(groupID, toRemove)
	if err := c.withGroupProjectAdminGuardLocks(ctx, groupID, guard, func(ctx context.Context, fence txFence) error {
		if err := guard(ctx, c.storage); err != nil {
			return err
		}
		// All add/remove membership writes run in one transaction: a partial apply used
		// to be best-effort (`_ =`). Both AddUserToGroup and RemoveUserFromGroup are
		// idempotent (a duplicate add / already-gone remove is a no-op, not an error),
		// so a fatal error here from a genuine storage failure — and a retry of the
		// SAME PATCH after it — stay safe; this only changes the transient-failure case
		// from "silently half-applied" to "rolled back, retry re-applies cleanly."
		// Wrapped in ErrorStorageFailed HERE, inside the closure, so the guard
		// checks above (returned bare, their own message is already specific)
		// aren't also mislabeled as a storage failure by the caller below.
		//
		// AUDIT-TX-3: the rename and the audit row run in this same transaction. A
		// change that adds members or renames the group can widen access, so its
		// row commits with it or not at all; a pure removal is a revocation, never
		// blocked by the audit log, its row owed from the transaction. Both at once is
		// split, decided on the membership read under these locks: the removals here
		// (owed), the rest after the locks (fail closed).
		if widens && len(toRemove) > 0 {
			split = c.scimRemovesAMember(ctx, groupID, toRemove)
		}
		if split {
			var rerr error
			settle, rerr = c.runOwedAuditMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
				if err := fence(ctx, tx); err != nil {
					return err
				}
				for _, id := range toRemove {
					if err := tx.RemoveUserFromGroup(ctx, id, groupID, 0); err != nil { // SCIM memberships are always global
						return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
					}
				}
				c.writeAuditEventFullOn(ctx, tgt, EventSCIMGroupUpdated, actorPtr(actorID), nil, nil, "",
					fmt.Sprintf("SCIM patched group %d (-%d members)", groupID, len(removeIDs)))
				return nil
			})
			return rerr
		}
		if err := c.withAuditedOrOwedMutation(ctx, widens, func(tx storage.Storage, tgt auditTarget) error {
			if err := fence(ctx, tx); err != nil {
				return err
			}
			if renaming {
				matched, uerr := tx.UpdateGroupFields(ctx, groupID, newName, &folded, nil, c.now())
				if uerr != nil {
					return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), uerr)
				}
				if !matched {
					return fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), storage.ErrGroupNotFound)
				}
			}
			for _, id := range allowedAdds {
				if err := tx.AddUserToGroup(ctx, id, groupID, 0); err != nil { // SCIM memberships are always global
					return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
				}
			}
			for _, id := range toRemove {
				if err := tx.RemoveUserFromGroup(ctx, id, groupID, 0); err != nil { // SCIM memberships are always global
					return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
				}
			}
			c.writeAuditEventFullOn(ctx, tgt, EventSCIMGroupUpdated, actorPtr(actorID), nil, nil, "",
				fmt.Sprintf("SCIM patched group %d (+%d/-%d members)", groupID, len(addIDs), len(removeIDs)))
			if !widens {
				return nil // a revocation: read back after the commit, below
			}
			var rerr error
			state, rerr = c.readSCIMGroupState(ctx, tx, groupID)
			return rerr
		}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if !widens {
		if err := readBackAfterRevocation(func() (rerr error) {
			state, rerr = c.readSCIMGroupState(ctx, c.storage, groupID)
			return rerr
		}); err != nil {
			return nil, err
		}
		return state, nil
	}
	if split {
		// After the guard locks (F6: the owed row never settles under them), then
		// commit 2: the rename and the adds, fail closed. A retry of the same PATCH
		// removes nothing more (the members are gone), so it is fail closed as a whole.
		settle()
		if err := c.commitSplitRemainder(ctx, "member removal", "member addition/rename", true, func(tx storage.Storage, tgt auditTarget) error {
			if renaming {
				matched, uerr := tx.UpdateGroupFields(ctx, groupID, newName, &folded, nil, c.now())
				if uerr != nil {
					return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), uerr)
				}
				if !matched {
					return fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), storage.ErrGroupNotFound)
				}
			}
			for _, id := range allowedAdds {
				if err := tx.AddUserToGroup(ctx, id, groupID, 0); err != nil { // SCIM memberships are always global
					return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
				}
			}
			c.writeAuditEventFullOn(ctx, tgt, EventSCIMGroupUpdated, actorPtr(actorID), nil, nil, "",
				fmt.Sprintf("SCIM patched group %d (+%d members)", groupID, len(addIDs)))
			var rerr error
			state, rerr = c.readSCIMGroupState(ctx, tx, groupID)
			return rerr
		}); err != nil {
			return nil, err
		}
	}
	return state, nil
}

// scimRemovesAMember reports whether removing ids from groupID removes at least one
// current member (read under the caller's guard locks). A failed read counts as yes:
// splitting a request that removes nothing only costs a second commit, while not
// splitting one that does would let the audit log block its revocation.
func (c *KeyorixCore) scimRemovesAMember(ctx context.Context, groupID uint, ids []uint) bool {
	members, err := c.storage.ListGroupMembers(ctx, groupID)
	if err != nil {
		return true
	}
	for _, m := range members {
		if slices.Contains(ids, m.ID) {
			return true
		}
	}
	return false
}

// refuseAddToAdminGroup is the SCIM group-sync backstop against privilege escalation:
// it returns ErrSCIMGroupConfersAdmin when membership in groupID grants an
// escalation-tier role, so the SCIM paths refuse to add members to it (the SSO
// group-membership path, sso.go, applies the same predicate). "Escalation-tier" is the
// shared idpAutoGrantOfRoleIsEscalation predicate: a canonical admin role, an
// admin-bypass role, OR a role carrying roles.assign (the role-granting primitive — a
// self-service group member who obtains it becomes a privilege pump). Fails CLOSED on a
// GetGroupRoles lookup error — and idpAutoGrantOfRoleIsEscalation itself fails closed on
// a per-role resolution error (#G17-style: a lookup failure must not be
// indistinguishable from a legitimate negative result) — so an inability to verify never
// opens the grant. The lookup failure is returned as itself, not as the refusal: it is
// a server error the IdP retries, where the refusal is permanent (#3620).
func (c *KeyorixCore) refuseAddToAdminGroup(ctx context.Context, groupID uint) error {
	confers, err := c.idpGroupConfersAdminVerdict(ctx, groupID)
	if confers {
		return fmt.Errorf("%s: %w", i18n.T("ErrorNotAuthorized", nil), ErrSCIMGroupConfersAdmin)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return nil
}

// idpGroupConfersAdminVerdict is refuseAddToAdminGroup's predicate with a lookup failure
// kept apart from the verdict (err != nil: nothing decided). See
// idpAutoGrantEscalationVerdict for why SSO reconcile needs the difference.
// A role that IS an escalation decides the answer even if a sibling role's
// lookup failed: "confers admin" is already known, so the error is moot.
func (c *KeyorixCore) idpGroupConfersAdminVerdict(ctx context.Context, groupID uint) (bool, error) {
	roles, err := c.storage.GetGroupRoles(ctx, groupID)
	if err != nil {
		return false, fmt.Errorf("resolving group %d's roles: %w", groupID, err)
	}
	var firstErr error
	for _, r := range roles {
		escalation, verr := c.idpAutoGrantEscalationVerdict(ctx, r.ID, r.Name)
		if escalation {
			return true, nil
		}
		if verr != nil && firstErr == nil {
			firstErr = verr
		}
	}
	return false, firstErr
}

func buildSCIMMemberMaps(memberIDs []uint, current []*models.User) (want, have map[uint]bool) {
	want = make(map[uint]bool, len(memberIDs))
	for _, id := range memberIDs {
		if id != 0 {
			want[id] = true
		}
	}
	have = make(map[uint]bool, len(current))
	for _, u := range current {
		have[u.ID] = true
	}
	return want, have
}

func computeSCIMToAdd(want, have map[uint]bool) []uint {
	toAdd := make([]uint, 0)
	for id := range want {
		if !have[id] {
			toAdd = append(toAdd, id)
		}
	}
	return toAdd
}

func hasSCIMAdditions(addIDs []uint) bool {
	for _, id := range addIDs {
		if id != 0 {
			return true
		}
	}
	return false
}

func filterNonZero(ids []uint) []uint {
	out := make([]uint, 0, len(ids))
	for _, id := range ids {
		if id != 0 {
			out = append(out, id)
		}
	}
	return out
}

// applyGroupMembershipChanges applies the add/remove sets computed by the
// caller. Every removal is checked against guardLastGlobalAdminMembership
// (#G02) and guardLastProjectAdminGroupMembership (core-project-members.json#3)
// BEFORE any storage write happens, so a SCIM PUT that would strip the
// install's last route to global-admin authority, or a project's last
// roles.assign holder, is refused atomically — not applied member-by-member
// with some removals already committed.
//
// SESSION-AT #2352: guard checks + the write both now run under
// withGroupProjectAdminGuardLocks — an earlier version ran the guard checks
// with no lock at all, so two concurrent membership changes (this same PUT
// racing a SCIM PATCH or a native RemoveUserFromGroup) could each observe
// "another admin survives" before either commits.
//
// AUDIT-TX-3: rename (optional) and audit run in the same transaction as the
// membership writes. A change that adds members or renames the group can widen
// access, so its audit row commits with it or not at all; a pure removal is a
// revocation, never blocked by the audit log, its row owed from the transaction.
// Both at once (a removal that really removes a member, decided on the membership
// read under the guard locks, plus an add or a rename) is a mixed request
// (MERGE-FIX-3482G): the removals commit alone under the locks (owed, their row
// written by auditRemovals), and the rename and adds follow after the locks as their
// own fail-closed commit (audit writes its row).
//
// readBack reads the state the response renders: inside the last transaction when
// the change widens, after the commit for a pure removal (SCIMGroupState).
func (c *KeyorixCore) applyGroupMembershipChanges(ctx context.Context, groupID uint, want map[uint]bool, current []*models.User, toAdd []uint, rename func(tx storage.Storage) error, auditRemovals, audit func(tgt auditTarget), readBack func(tx storage.Storage) error) error {
	var removals []uint
	for _, u := range current {
		if !want[u.ID] {
			removals = append(removals, u.ID)
		}
	}
	widens := len(toAdd) > 0 || rename != nil
	var split bool
	var settle func()
	guard := scimRemovalsGuard(groupID, removals)
	if err := c.withGroupProjectAdminGuardLocks(ctx, groupID, guard, func(ctx context.Context, fence txFence) error {
		if err := guard(ctx, c.storage); err != nil {
			return err
		}
		removeAll := func(tx storage.Storage) error {
			for _, id := range removals {
				if err := tx.RemoveUserFromGroup(ctx, id, groupID, 0); err != nil { // SCIM memberships are always global
					return err
				}
			}
			return nil
		}
		if widens && len(removals) > 0 {
			split = c.scimRemovesAMember(ctx, groupID, removals)
		}
		if split {
			var rerr error
			settle, rerr = c.runOwedAuditMutation(ctx, func(tx storage.Storage, tgt auditTarget) error {
				if err := fence(ctx, tx); err != nil {
					return err
				}
				if err := removeAll(tx); err != nil {
					return err
				}
				auditRemovals(tgt)
				return nil
			})
			return rerr
		}
		// All add/remove membership writes run in one transaction: a partial apply used
		// to be best-effort (`_ =`). Both storage calls are idempotent, so this stays
		// safe under an IdP's own retry of the same PUT.
		return c.withAuditedOrOwedMutation(ctx, widens, func(tx storage.Storage, tgt auditTarget) error {
			if err := fence(ctx, tx); err != nil {
				return err
			}
			if rename != nil {
				if err := rename(tx); err != nil {
					return err
				}
			}
			if err := removeAll(tx); err != nil {
				return err
			}
			for _, id := range toAdd {
				if err := tx.AddUserToGroup(ctx, id, groupID, 0); err != nil { // SCIM memberships are always global
					return err
				}
			}
			audit(tgt)
			if !widens {
				return nil // a revocation: read back after the commit, below
			}
			return readBack(tx)
		})
	}); err != nil {
		return err
	}
	if !widens {
		// A pure removal committed (owed): its read-back must not be able to roll it
		// back, so it reads outside the transaction and a failure is reported as
		// applied (ErrSCIMGroupStateUnavailable).
		return readBackAfterRevocation(func() error { return readBack(c.storage) })
	}
	if !split {
		return nil
	}
	// After the guard locks (F6: the owed row never settles under them), then commit 2.
	// A retry of the same PUT removes nothing more, so it is fail closed as a whole.
	settle()
	return c.commitSplitRemainder(ctx, "member removal", "member addition/rename", true, func(tx storage.Storage, tgt auditTarget) error {
		if rename != nil {
			if err := rename(tx); err != nil {
				return err
			}
		}
		for _, id := range toAdd {
			if err := tx.AddUserToGroup(ctx, id, groupID, 0); err != nil { // SCIM memberships are always global
				return err
			}
		}
		audit(tgt)
		return readBack(tx)
	})
}

// DeprovisionSCIMGroup handles a SCIM DELETE — removes the group (membership links
// go with it). Refuses to delete a group holding the install's last
// global-admin-conferring role grant (guardLastGlobalAdminGroupDelete, #G02) or
// any project's last roles.assign-conferring grant
// (guardLastProjectAdminGroupDelete, core-project-members.json#3) — the same
// guards the native DeleteGroup already applies.
//
// SESSION-AT #2352: this used to call c.storage.DeleteGroup directly after its
// own, UNLOCKED guard checks — bypassing core.DeleteGroup's lock entirely (it
// never called DeleteGroup at all, it duplicated the guard logic and then went
// storage-direct). A SCIM DELETE racing a native DeleteGroup, another SCIM
// DELETE, or any other group-wide admin-removing operation could each observe
// "another admin survives" before either commits. Now shares DeleteGroup's own
// deleteGroupGuarded helper (groups.go) — guard + lock + write identical to the
// native path — and only the audit event differs.
func (c *KeyorixCore) DeprovisionSCIMGroup(ctx context.Context, actorID, groupID uint) error {
	_, err := c.deleteGroupGuarded(ctx, groupID, func(tgt auditTarget, _ *models.Group) {
		c.writeAuditEventFullOn(ctx, tgt, EventSCIMGroupDeprovisioned, actorPtr(actorID), nil, nil, "",
			fmt.Sprintf("SCIM deprovisioned group %d", groupID))
	})
	return err
}

// scimRemovalsGuard is the last-admin guard a SCIM membership change runs for
// each member it removes (global and project), read through st: before the
// write transaction on c.storage, and again inside it through tx
// (withGroupProjectAdminGuardLocks' fence, NAMEDLOCK-OVERLAP-2).
func scimRemovalsGuard(groupID uint, removals []uint) func(ctx context.Context, st storage.Storage) error {
	return func(ctx context.Context, st storage.Storage) error {
		for _, id := range removals {
			if err := guardLastGlobalAdminMembershipOn(ctx, st, id, groupID); err != nil {
				return err
			}
			if err := guardLastProjectAdminGroupMembershipOn(ctx, st, id, groupID); err != nil {
				return err
			}
		}
		return nil
	}
}
