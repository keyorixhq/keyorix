// access_review.go — access recertification (ISO 27001 A.5.18 / SOC 2 CC6.2-6.3).
//
// GenerateProjectAccessReview enumerates who can reach a project's secrets and how:
// the role-based standing access (project-scoped role grants whose role confers a
// secrets.* permission) plus the per-secret grants (ownership and direct/group
// shares). Each entry's Source says which mechanism conferred the access.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AccessReviewEntry is one grant of access to a project's secrets, for an access
// review. Source distinguishes how the access is conferred:
//   - "role"          — a project-scoped role grant (project-wide; SecretID 0,
//     RoleName set, AccessLevel = the role's highest secrets.* action)
//   - "owner"         — the principal owns a specific secret (SecretID set)
//   - "direct_share"  — a secret shared directly with a user (SecretID set)
//   - "group_share"   — a secret shared with a group (SecretID set)
type AccessReviewEntry struct {
	PrincipalType string `json:"principal_type"` // "user" | "group"
	PrincipalID   uint   `json:"principal_id"`
	PrincipalName string `json:"principal_name"` // username or group name
	Email         string `json:"email,omitempty"`
	Source        string `json:"source"` // role | owner | direct_share | group_share
	RoleID        uint   `json:"role_id,omitempty"`
	RoleName      string `json:"role_name,omitempty"`
	AccessLevel   string `json:"access_level"`   // read|write|delete|admin (role) or read|write|owner (share)
	EnvironmentID uint   `json:"environment_id"` // 0 = the whole project (role grants)
	SecretID      uint   `json:"secret_id,omitempty"`
	SecretName    string `json:"secret_name,omitempty"`
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

// GenerateProjectAccessReview returns every grant of access to a project's secrets
// (ISO 27001 A.5.18): the role-based standing access (project-scoped role grants
// whose role confers a secrets.* permission) and the per-secret grants (ownership
// and direct/group shares). Each entry's Source identifies the mechanism.
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

	userCache := map[uint][2]string{} // id -> {name, email}
	resolveUser := func(id uint) (string, string) {
		if ne, ok := userCache[id]; ok {
			return ne[0], ne[1]
		}
		ne := [2]string{}
		if u, err := c.storage.GetUser(ctx, id); err == nil && u != nil {
			ne = [2]string{u.Username, u.Email}
		}
		userCache[id] = ne
		return ne[0], ne[1]
	}
	groupCache := map[uint]string{}
	resolveGroup := func(id uint) string {
		if n, ok := groupCache[id]; ok {
			return n
		}
		n := ""
		if g, err := c.storage.GetGroup(ctx, id); err == nil && g != nil {
			n = g.Name
		}
		groupCache[id] = n
		return n
	}

	var entries []*AccessReviewEntry

	// (1) Role-based standing access — project-scoped role grants whose role confers
	// a secrets.* permission. Applies project-wide (no specific secret).
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
			Source:        "role",
			RoleID:        a.RoleID,
			RoleName:      ri.name,
			AccessLevel:   ri.action,
			EnvironmentID: a.EnvironmentID,
		}
		if a.PrincipalType == "group" {
			entry.PrincipalName = resolveGroup(a.PrincipalID)
		} else {
			entry.PrincipalName, entry.Email = resolveUser(a.PrincipalID)
		}
		entries = append(entries, entry)
	}

	// (2) Per-secret grants — ownership plus direct/group shares (the granular
	// exceptions, beyond the project's role-based access).
	secrets, err := c.listAllProjectSecrets(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, s := range secrets {
		if s.OwnerID != 0 {
			name, email := resolveUser(s.OwnerID)
			entries = append(entries, &AccessReviewEntry{
				PrincipalType: "user", PrincipalID: s.OwnerID, PrincipalName: name, Email: email,
				Source: "owner", AccessLevel: "owner", SecretID: s.ID, SecretName: s.Name,
			})
		}
		shares, err := c.storage.ListSharesBySecret(ctx, s.ID)
		if err != nil {
			continue // best-effort; a secret whose shares can't be read is skipped
		}
		for _, sh := range shares {
			e := &AccessReviewEntry{
				PrincipalID: sh.RecipientID, AccessLevel: sh.Permission,
				SecretID: s.ID, SecretName: s.Name,
			}
			if sh.IsGroup {
				e.PrincipalType, e.Source = "group", "group_share"
				e.PrincipalName = resolveGroup(sh.RecipientID)
			} else {
				e.PrincipalType, e.Source = "user", "direct_share"
				e.PrincipalName, e.Email = resolveUser(sh.RecipientID)
			}
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// listAllProjectSecrets pages through every secret in a project (no silent cap).
func (c *KeyorixCore) listAllProjectSecrets(ctx context.Context, projectID uint) ([]*models.SecretNode, error) {
	const pageSize = 500
	pid := projectID
	var all []*models.SecretNode
	for page := 1; ; page++ {
		secrets, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
			ProjectID: &pid, Page: page, PageSize: pageSize,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, secrets...)
		if len(secrets) < pageSize || int64(len(all)) >= total {
			break
		}
	}
	return all, nil
}
