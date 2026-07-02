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

// ProvisionSCIMGroup creates a group from a SCIM Create and adds its initial members.
func (c *KeyorixCore) ProvisionSCIMGroup(ctx context.Context, actorID uint, displayName string, memberIDs []uint) (*models.Group, error) {
	if displayName == "" {
		return nil, fmt.Errorf("displayName is required")
	}
	// Storage-direct: the SCIM path emits its own scim.group_provisioned event below,
	// so it must not also fire the generic group.created from CreateGroup.
	group, err := c.storage.CreateGroup(ctx, &models.Group{Name: displayName})
	if err != nil {
		return nil, err
	}
	for _, uid := range memberIDs {
		if uid != 0 {
			_ = c.storage.AddUserToGroup(ctx, uid, group.ID)
		}
	}
	c.writeAuditEvent(ctx, EventSCIMGroupProvisioned, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM provisioned group %d (%q) with %d member(s)", group.ID, displayName, len(memberIDs)))
	return group, nil
}

// ReplaceSCIMGroup applies a SCIM Replace (PUT): an optional rename plus the FULL
// member set (members not in memberIDs are removed; new ones are added).
func (c *KeyorixCore) ReplaceSCIMGroup(ctx context.Context, actorID, groupID uint, displayName string, memberIDs []uint) (*models.Group, error) {
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
	want := make(map[uint]bool, len(memberIDs))
	for _, id := range memberIDs {
		if id != 0 {
			want[id] = true
		}
	}
	have := make(map[uint]bool, len(current))
	for _, u := range current {
		have[u.ID] = true
	}
	toAdd := make([]uint, 0)
	for id := range want {
		if !have[id] {
			toAdd = append(toAdd, id)
		}
	}
	// SCIM must not be able to grant administrative access by adding members to a group
	// that carries an admin role. Block the add (de-escalating removals are still fine).
	if len(toAdd) > 0 && c.scimGroupConfersAdmin(ctx, groupID) {
		return nil, fmt.Errorf("%s: SCIM cannot add members to a group that grants administrative roles", i18n.T("ErrorNotAuthorized", nil))
	}
	for _, u := range current {
		if !want[u.ID] {
			_ = c.storage.RemoveUserFromGroup(ctx, u.ID, groupID)
		}
	}
	for _, id := range toAdd {
		_ = c.storage.AddUserToGroup(ctx, id, groupID)
	}
	c.writeAuditEvent(ctx, EventSCIMGroupUpdated, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM replaced group %d (members=%d)", groupID, len(want)))
	return c.storage.GetGroup(ctx, groupID)
}

// PatchSCIMGroup applies a SCIM PATCH: an optional rename plus incremental member
// add/remove. nil newName leaves the name unchanged.
func (c *KeyorixCore) PatchSCIMGroup(ctx context.Context, actorID, groupID uint, newName *string, addIDs, removeIDs []uint) (*models.Group, error) {
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
	hasAdds := false
	for _, id := range addIDs {
		if id != 0 {
			hasAdds = true
			break
		}
	}
	if hasAdds && c.scimGroupConfersAdmin(ctx, groupID) {
		return nil, fmt.Errorf("%s: SCIM cannot add members to a group that grants administrative roles", i18n.T("ErrorNotAuthorized", nil))
	}
	for _, id := range addIDs {
		if id != 0 {
			_ = c.storage.AddUserToGroup(ctx, id, groupID)
		}
	}
	for _, id := range removeIDs {
		if id != 0 {
			_ = c.storage.RemoveUserFromGroup(ctx, id, groupID)
		}
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

// DeprovisionSCIMGroup handles a SCIM DELETE — removes the group (membership links
// go with it).
func (c *KeyorixCore) DeprovisionSCIMGroup(ctx context.Context, actorID, groupID uint) error {
	// Storage-direct: the SCIM path emits scim.group_deprovisioned below, not the
	// generic group.deleted. storage.DeleteGroup still errors on a missing group.
	if err := c.storage.DeleteGroup(ctx, groupID); err != nil {
		return err
	}
	c.writeAuditEvent(ctx, EventSCIMGroupDeprovisioned, actorPtr(actorID), nil,
		fmt.Sprintf("SCIM deprovisioned group %d", groupID))
	return nil
}
