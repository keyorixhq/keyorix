// scim_groups.go — SCIM 2.0 group sync (RFC 7644), the companion to scim.go. An IdP
// creates groups and pushes their membership; Keyorix maps a SCIM Group to a native
// Group (displayName → Name) and its members to user↔group links. PUT replaces the
// full member set; PATCH adds/removes members (and may rename). All mutations are
// audited.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
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

// scimManagedMember reports whether uid identifies a SCIM-managed account (carries a
// stored ExternalID — only SCIM user-provisioning sets one; a native/local account
// never does). SCIM group membership mutations (Create/Replace/PATCH) must refuse any
// target that isn't: those endpoints take arbitrary numeric member ids straight off
// the SCIM payload with no check that the id belongs to an account SCIM actually owns,
// so a valid (e.g. group-provisioning-only) SCIM bearer token could otherwise add ANY
// native user — including one the attacker already controls — into a group. If that
// group carries an admin-conferring role (a common "IdP group X = Keyorix admins"
// integration pattern), membership alone grants the role immediately, with no SSO
// step required (#167 — the group-membership sibling of #120's user-level guard).
// Fails CLOSED (treats a lookup error as not-managed) so an inability to verify never
// opens the add.
func (c *KeyorixCore) scimManagedMember(ctx context.Context, uid uint) bool {
	user, err := c.storage.GetUser(ctx, uid)
	if err != nil {
		return false
	}
	return user.ExternalID != ""
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
// rest as refused rather than silently dropping them.
func (c *KeyorixCore) filterSCIMManaged(ctx context.Context, ids []uint) (allowed, rejected []uint) { // nosemgrep: keyorix-unbounded-bulk-slice-param -- all three callers (ProvisionSCIMGroup, ReplaceSCIMGroup, PatchSCIMGroup) enforce maxSCIMGroupMembersPerCall on their raw incoming id list before calling this
	for _, id := range ids {
		if id == 0 {
			continue
		}
		if c.scimManagedMember(ctx, id) {
			allowed = append(allowed, id)
		} else {
			rejected = append(rejected, id)
		}
	}
	return allowed, rejected
}

// ProvisionSCIMGroup creates a group from a SCIM Create and adds its initial members.
// Only SCIM-managed members may be added (scimManagedMember, #167); a non-SCIM-managed
// id in memberIDs is refused.
func (c *KeyorixCore) ProvisionSCIMGroup(ctx context.Context, actorID uint, displayName string, memberIDs []uint) (*models.Group, error) {
	if displayName == "" {
		return nil, fmt.Errorf("displayName is required")
	}
	if len(memberIDs) > maxSCIMGroupMembersPerCall {
		return nil, fmt.Errorf("memberIDs exceeds the maximum batch size of %d", maxSCIMGroupMembersPerCall)
	}
	allowed, rejected := c.filterSCIMManaged(ctx, memberIDs)
	if len(rejected) > 0 {
		return nil, fmt.Errorf("%s: SCIM can only add SCIM-managed users to a group (rejected member id(s): %v)", i18n.T("ErrorNotAuthorized", nil), rejected)
	}
	// Storage-direct: the SCIM path emits its own scim.group_provisioned event below,
	// so it must not also fire the generic group.created from CreateGroup.
	group, err := c.storage.CreateGroup(ctx, &models.Group{Name: displayName})
	if err != nil {
		return nil, err
	}
	for _, uid := range allowed {
		_ = c.storage.AddUserToGroup(ctx, uid, group.ID, 0) // SCIM memberships are always global
	}
	c.writeAuditEvent(ctx, EventSCIMGroupProvisioned, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM provisioned group %d (%q) with %d member(s)", group.ID, displayName, len(allowed)))
	return group, nil
}

// ReplaceSCIMGroup applies a SCIM Replace (PUT): an optional rename plus the FULL
// member set (members not in memberIDs are removed; new ones are added).
func (c *KeyorixCore) ReplaceSCIMGroup(ctx context.Context, actorID, groupID uint, displayName string, memberIDs []uint) (*models.Group, error) {
	if len(memberIDs) > maxSCIMGroupMembersPerCall {
		return nil, fmt.Errorf("memberIDs exceeds the maximum batch size of %d", maxSCIMGroupMembersPerCall)
	}
	group, err := c.storage.GetGroup(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	if displayName != "" && displayName != group.Name {
		group.Name = displayName
		if _, err := c.storage.UpdateGroup(ctx, group); err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
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
	if len(toAdd) > 0 && c.scimGroupConfersAdmin(ctx, groupID) {
		return nil, fmt.Errorf("%s: SCIM cannot add members to a group that grants administrative roles", i18n.T("ErrorNotAuthorized", nil))
	}
	// Every add must target a SCIM-managed account (#167); a native/non-SCIM id in the
	// requested member set is refused outright rather than silently skipped.
	if _, rejected := c.filterSCIMManaged(ctx, toAdd); len(rejected) > 0 {
		return nil, fmt.Errorf("%s: SCIM can only add SCIM-managed users to a group (rejected member id(s): %v)", i18n.T("ErrorNotAuthorized", nil), rejected)
	}
	if err := c.applyGroupMembershipChanges(ctx, groupID, want, current, toAdd); err != nil {
		return nil, err
	}
	c.writeAuditEvent(ctx, EventSCIMGroupUpdated, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM replaced group %d (members=%d)", groupID, len(want)))
	return c.storage.GetGroup(ctx, groupID)
}

// PatchSCIMGroup applies a SCIM PATCH: an optional rename plus incremental member
// add/remove. nil newName leaves the name unchanged.
func (c *KeyorixCore) PatchSCIMGroup(ctx context.Context, actorID, groupID uint, newName *string, addIDs, removeIDs []uint) (*models.Group, error) {
	if len(addIDs) > maxSCIMGroupMembersPerCall || len(removeIDs) > maxSCIMGroupMembersPerCall {
		return nil, fmt.Errorf("addIDs/removeIDs exceeds the maximum batch size of %d", maxSCIMGroupMembersPerCall)
	}
	group, err := c.storage.GetGroup(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	if newName != nil && *newName != "" && *newName != group.Name {
		group.Name = *newName
		if _, err := c.storage.UpdateGroup(ctx, group); err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
	}
	if hasSCIMAdditions(addIDs) && c.scimGroupConfersAdmin(ctx, groupID) {
		return nil, fmt.Errorf("%s: SCIM cannot add members to a group that grants administrative roles", i18n.T("ErrorNotAuthorized", nil))
	}
	// Every add must target a SCIM-managed account (#167); a native/non-SCIM id in the
	// requested add set is refused outright rather than silently skipped.
	allowedAdds, rejected := c.filterSCIMManaged(ctx, addIDs)
	if len(rejected) > 0 {
		return nil, fmt.Errorf("%s: SCIM can only add SCIM-managed users to a group (rejected member id(s): %v)", i18n.T("ErrorNotAuthorized", nil), rejected)
	}
	// Check every removal against guardLastGlobalAdminMembership (#G02) BEFORE
	// applying any of them, so a PATCH that would strip the install's last route
	// to global-admin authority is refused atomically — see
	// applyGroupMembershipChanges's identical precheck-then-apply shape.
	toRemove := filterNonZero(removeIDs)
	for _, id := range toRemove {
		if err := c.guardLastGlobalAdminMembership(ctx, id, groupID); err != nil {
			return nil, err
		}
	}
	for _, id := range allowedAdds {
		_ = c.storage.AddUserToGroup(ctx, id, groupID, 0) // SCIM memberships are always global
	}
	for _, id := range toRemove {
		_ = c.storage.RemoveUserFromGroup(ctx, id, groupID, 0) // SCIM memberships are always global
	}
	c.writeAuditEvent(ctx, EventSCIMGroupUpdated, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM patched group %d (+%d/-%d members)", groupID, len(addIDs), len(removeIDs)))
	return c.storage.GetGroup(ctx, groupID)
}

// scimGroupConfersAdmin reports whether membership in groupID grants an admin role, so
// the SCIM group-sync paths can refuse to add members to it. Fails CLOSED (treats the
// group as admin-bearing) on a lookup error, so an inability to verify never opens the
// privilege grant.
func (c *KeyorixCore) scimGroupConfersAdmin(ctx context.Context, groupID uint) bool {
	roles, err := c.storage.GetGroupRoles(ctx, groupID)
	if err != nil {
		return true
	}
	ids := make([]uint, 0, len(roles))
	for _, r := range roles {
		ids = append(ids, r.ID)
	}
	return c.roleSetContainsAdmin(ctx, ids)
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
// (#G02) BEFORE any storage write happens, so a SCIM PUT that would strip the
// install's last route to global-admin authority is refused atomically — not
// applied member-by-member with some removals already committed.
func (c *KeyorixCore) applyGroupMembershipChanges(ctx context.Context, groupID uint, want map[uint]bool, current []*models.User, toAdd []uint) error {
	for _, u := range current {
		if !want[u.ID] {
			if err := c.guardLastGlobalAdminMembership(ctx, u.ID, groupID); err != nil {
				return err
			}
		}
	}
	for _, u := range current {
		if !want[u.ID] {
			_ = c.storage.RemoveUserFromGroup(ctx, u.ID, groupID, 0) // SCIM memberships are always global
		}
	}
	for _, id := range toAdd {
		_ = c.storage.AddUserToGroup(ctx, id, groupID, 0) // SCIM memberships are always global
	}
	return nil
}

// DeprovisionSCIMGroup handles a SCIM DELETE — removes the group (membership links
// go with it). Refuses to delete a group holding the install's last
// global-admin-conferring role grant (guardLastGlobalAdminGroupDelete, #G02) —
// the same guard the native DeleteGroup already applies.
func (c *KeyorixCore) DeprovisionSCIMGroup(ctx context.Context, actorID, groupID uint) error {
	if err := c.guardLastGlobalAdminGroupDelete(ctx, groupID); err != nil {
		return err
	}
	// Storage-direct: the SCIM path emits scim.group_deprovisioned below, not the
	// generic group.deleted. storage.DeleteGroup still errors on a missing group.
	if err := c.storage.DeleteGroup(ctx, groupID); err != nil {
		return err
	}
	c.writeAuditEvent(ctx, EventSCIMGroupDeprovisioned, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM deprovisioned group %d", groupID))
	return nil
}
