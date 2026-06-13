// access_review.go — access recertification (ISO 27001 A.5.18 / SOC 2 CC6.2-6.3).
//
// GenerateProjectAccessReview enumerates the *role-based* standing access to a
// project's secrets: every project-scoped role grant (to a user or a group) whose
// role confers a secrets.* permission, with the highest secrets action it grants.
// This is the primary recertification surface — "who can reach this project's
// secrets via their assigned role, and at what level". Per-secret share grants
// (the granular exceptions) are a separate review surface.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AccessReviewEntry is one principal's role-based access to a project's secrets.
type AccessReviewEntry struct {
	PrincipalType string `json:"principal_type"` // "user" | "group"
	PrincipalID   uint   `json:"principal_id"`
	PrincipalName string `json:"principal_name"` // username or group name
	Email         string `json:"email,omitempty"`
	RoleName      string `json:"role_name"`
	AccessLevel   string `json:"access_level"`   // highest secrets.* action: read|write|delete|admin
	EnvironmentID uint   `json:"environment_id"` // 0 = the whole project
}

// secretsActionRank orders secrets.* actions so a review reports the strongest
// access a role confers.
var secretsActionRank = map[string]int{"read": 1, "write": 2, "delete": 3, "admin": 4}

// highestSecretsAction returns the strongest secrets.* action in a permission set,
// or "" when the role grants no secret access at all.
func highestSecretsAction(perms []*models.Permission) string {
	best, bestRank := "", 0
	for _, p := range perms {
		if p.Resource != "secrets" {
			continue
		}
		if r := secretsActionRank[p.Action]; r > bestRank {
			best, bestRank = p.Action, r
		}
	}
	return best
}

// GenerateProjectAccessReview returns the role-based access principals for a
// project's secrets (ISO 27001 A.5.18). Each entry is a (principal, role) grant
// scoped to the project whose role confers a secrets.* permission. A principal
// with several qualifying roles yields several entries.
func (c *KeyorixCore) GenerateProjectAccessReview(ctx context.Context, projectID uint) ([]*AccessReviewEntry, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}

	assignments, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	type roleInfo struct{ name, action string }
	roleCache := map[uint]roleInfo{}
	resolveRole := func(roleID uint) (roleInfo, error) {
		if ri, ok := roleCache[roleID]; ok {
			return ri, nil
		}
		perms, err := c.storage.GetRolePermissions(ctx, roleID)
		if err != nil {
			return roleInfo{}, err
		}
		ri := roleInfo{action: highestSecretsAction(perms)}
		if role, err := c.storage.GetRole(ctx, roleID); err == nil && role != nil {
			ri.name = role.Name
		}
		roleCache[roleID] = ri
		return ri, nil
	}

	userNames := map[uint][2]string{} // id -> {name, email}
	groupNames := map[uint]string{}

	var entries []*AccessReviewEntry
	for _, a := range assignments {
		ri, err := resolveRole(a.RoleID)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		if ri.action == "" {
			continue // role grants no secret access — not a secret-access reviewer
		}

		entry := &AccessReviewEntry{
			PrincipalType: a.PrincipalType,
			PrincipalID:   a.PrincipalID,
			RoleName:      ri.name,
			AccessLevel:   ri.action,
			EnvironmentID: a.EnvironmentID,
		}
		switch a.PrincipalType {
		case "group":
			name, ok := groupNames[a.PrincipalID]
			if !ok {
				if g, err := c.storage.GetGroup(ctx, a.PrincipalID); err == nil && g != nil {
					name = g.Name
				}
				groupNames[a.PrincipalID] = name
			}
			entry.PrincipalName = name
		default: // user
			ne, ok := userNames[a.PrincipalID]
			if !ok {
				if u, err := c.storage.GetUser(ctx, a.PrincipalID); err == nil && u != nil {
					ne = [2]string{u.Username, u.Email}
				}
				userNames[a.PrincipalID] = ne
			}
			entry.PrincipalName, entry.Email = ne[0], ne[1]
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
