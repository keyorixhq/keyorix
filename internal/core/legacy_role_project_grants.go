// legacy_role_project_grants.go — #3605: the upgrade check for the legacy
// single-tier roles (admin, editor, viewer, auditor, super_admin), which are
// install-wide only since #3605. Grants of them already held at a project keep
// working and are not changed here: this names each one and how to replace it,
// for the startup notice and `keyorix-server admin validate --posture`.
package core

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// LegacyRoleProjectGrant is one existing per-project grant of a legacy role.
// Principal, Project and Environment are "" when the name cannot be resolved
// (for example a grant at a deleted project); the grant is still listed.
type LegacyRoleProjectGrant struct {
	PrincipalType string // "user", "group" or "machine"
	PrincipalID   uint
	Principal     string // the user's email, or the group's or machine's name
	RoleName      string
	Replacement   string // the project role to grant instead
	ProjectID     uint
	Project       string
	EnvironmentID uint
	Environment   string
	ExpiresAt     *time.Time // nil = permanent
}

// IsLegacyRoleAtProject reports whether g is a legacy role held at a project,
// the case ListLegacyRoleProjectGrants reports.
func (g RoleGrantOutsideScope) IsLegacyRoleAtProject() bool {
	_, ok := models.LegacyRoleProjectReplacement(g.RoleName)
	return ok && g.ProjectID != 0
}

// ListLegacyRoleProjectGrants returns every existing per-project grant of a
// legacy role, users, groups and machine identities alike, in the order of
// ListRoleGrantsOutsideAssignableScope. Read-only.
func (c *KeyorixCore) ListLegacyRoleProjectGrants(ctx context.Context) ([]LegacyRoleProjectGrant, error) {
	grants, err := c.ListRoleGrantsOutsideAssignableScope(ctx)
	if err != nil {
		return nil, err
	}
	projects, err := c.storage.ListProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	projectNames := make(map[uint]string, len(projects))
	for _, p := range projects {
		projectNames[p.ID] = p.Name
	}
	var out []LegacyRoleProjectGrant
	for _, g := range grants {
		if !g.IsLegacyRoleAtProject() {
			continue
		}
		replacement, _ := models.LegacyRoleProjectReplacement(g.RoleName)
		item := LegacyRoleProjectGrant{PrincipalType: g.PrincipalType, PrincipalID: g.PrincipalID,
			Principal: c.legacyGrantPrincipalName(ctx, g.PrincipalType, g.PrincipalID), RoleName: g.RoleName,
			Replacement: replacement, ProjectID: g.ProjectID, Project: projectNames[g.ProjectID],
			EnvironmentID: g.EnvironmentID, ExpiresAt: g.ExpiresAt}
		if g.EnvironmentID != 0 {
			if env, err := c.storage.GetEnvironment(ctx, g.EnvironmentID); err == nil && env != nil {
				item.Environment = env.Name
			}
		}
		out = append(out, item)
	}
	return out, nil
}

// legacyGrantPrincipalName resolves the name the CLI addresses a principal by.
// Best effort: "" means the grant is reported by ID.
func (c *KeyorixCore) legacyGrantPrincipalName(ctx context.Context, principalType string, id uint) string {
	switch principalType {
	case "user":
		if u, err := c.storage.GetUser(ctx, id); err == nil && u != nil {
			return u.Email
		}
	case "group":
		if g, err := c.storage.GetGroup(ctx, id); err == nil && g != nil {
			return g.Name
		}
	case "machine":
		if m, err := c.storage.GetMachineIdentity(ctx, id); err == nil && m != nil {
			return m.Name
		}
	}
	return ""
}

// Describe names the grant, for example "user a@example.com holds viewer on
// project payments".
func (g LegacyRoleProjectGrant) Describe() string {
	who := g.Principal
	if who == "" {
		who = fmt.Sprintf("id %d", g.PrincipalID)
	}
	where := g.Project
	if where == "" {
		where = fmt.Sprintf("id %d (deleted or not readable)", g.ProjectID)
	}
	s := fmt.Sprintf("%s %s holds %s on project %s", g.PrincipalType, who, g.RoleName, where)
	if g.EnvironmentID != 0 {
		if g.Environment != "" {
			s += ", environment " + g.Environment
		} else {
			s += fmt.Sprintf(", environment id %d", g.EnvironmentID)
		}
	}
	if g.ExpiresAt != nil {
		s += ", expires " + g.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return s
}

// ReplaceHint says how to replace the grant: the project role first, so access
// is never lost, then the legacy grant. Commands are given only when every name
// they need resolved.
func (g LegacyRoleProjectGrant) ReplaceHint() string {
	instead := "replace with " + g.Replacement
	if g.Project == "" {
		return instead + " if the project is restored; a grant at a deleted project authorizes nothing"
	}
	if g.Principal == "" || (g.EnvironmentID != 0 && g.Environment == "") {
		return instead + " through the API, using the IDs above"
	}
	if g.PrincipalType == "machine" && g.EnvironmentID != 0 {
		return instead + " through the API with environment_id (keyorix machine grant-role has no environment flag)"
	}
	grant, remove := g.cliCommands()
	hint := instead + ": " + grant + " && " + remove
	if g.ExpiresAt != nil {
		hint += " (add --ttl to the grant to keep it time-bound)"
	}
	return hint
}

// cliCommands returns the commands that grant the replacement and remove the
// legacy grant.
func (g LegacyRoleProjectGrant) cliCommands() (grant, remove string) {
	scope := " --project " + shellArg(g.Project)
	if g.EnvironmentID != 0 {
		scope += " --environment " + shellArg(g.Environment)
	}
	who := shellArg(g.Principal)
	switch g.PrincipalType {
	case "machine":
		return fmt.Sprintf("keyorix machine grant-role %s%s --role %s", who, scope, g.Replacement),
			fmt.Sprintf("keyorix machine revoke-role %s%s --role %s", who, scope, g.RoleName)
	case "group":
		return fmt.Sprintf("keyorix rbac assign-role-to-group --group %s --role %s%s", who, g.Replacement, scope),
			fmt.Sprintf("keyorix rbac remove-role-from-group --group %s --role %s%s", who, g.RoleName, scope)
	default:
		return fmt.Sprintf("keyorix rbac assign-role --user %s --role %s%s", who, g.Replacement, scope),
			fmt.Sprintf("keyorix rbac remove-role --user %s --role %s%s", who, g.RoleName, scope)
	}
}

// shellSafeArg matches a value that needs no quoting in a POSIX shell.
var shellSafeArg = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// shellArg quotes s for a command an operator will paste: names come from the
// database, so one must not be able to run anything.
func shellArg(s string) string {
	if shellSafeArg.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// LegacyEmergencyRoleWarning returns the warning for a break-glass emergency role
// that is a legacy role, "" otherwise. Break-glass grants at a project, so such a
// role now refuses every activation, which an operator would otherwise find out
// during an incident.
func LegacyEmergencyRoleWarning(emergencyRole string) string {
	replacement, ok := models.LegacyRoleProjectReplacement(strings.TrimSpace(emergencyRole))
	if !ok {
		return ""
	}
	return fmt.Sprintf("break_glass.emergency_role %s can no longer be granted on a project (#3605), so every break-glass activation is refused: "+
		"set it to %s, or another contained project role with no roles.assign", strings.TrimSpace(emergencyRole), replacement)
}

// LegacyRoleProjectGrantReport renders the check as lines, a heading and then
// one line per grant; nil when there are none. limit > 0 names at most limit
// grants and points to the complete list; 0 names all of them.
func LegacyRoleProjectGrantReport(grants []LegacyRoleProjectGrant, limit int) []string {
	if len(grants) == 0 {
		return nil
	}
	heading := fmt.Sprintf("%d existing per-project grant(s) of a legacy role (%s). New grants like these are refused since #3605; "+
		"these keep working and were left in place. To replace one, grant the project role, then remove the legacy grant.",
		len(grants), strings.Join(models.LegacyRoleNames(), ", "))
	for _, g := range grants {
		if g.RoleName == "viewer" {
			heading += " viewer includes audit.read and project_viewer does not: use project_auditor where that access is needed."
			break
		}
	}
	lines := []string{heading}
	for i, g := range grants {
		if limit > 0 && i == limit {
			lines = append(lines, fmt.Sprintf("... and %d more (keyorix-server admin validate --posture lists all of them)", len(grants)-i))
			break
		}
		lines = append(lines, g.Describe()+"; "+g.ReplaceHint())
	}
	return lines
}
