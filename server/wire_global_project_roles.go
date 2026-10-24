package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
)

// maxGlobalProjectRoleGrantLines bounds how many grants (and invitations) the
// startup notice names one by one; the total is always stated.
const maxGlobalProjectRoleGrantLines = 50

// wireGlobalProjectRoleGrantsNotice is a core wiring step (coreWiringSteps in
// main.go). GROUP-ROLE-SCOPE-1 (#3546): a grant outside its role's assignable
// scope is refused now; the important case is a project role held at the global
// scope, which applies in EVERY project. Existing grants are not touched (some
// may be relied on): this lists them, pending invitations that can no longer
// be accepted, and SSO settings that would create such grants, as a WARNING
// for an administrator to review. ROLE-SHAPE-1 adds grants at
// {project_id: 0, environment_id: X} of any role, which X's project's access
// review does not list. Read-only and best-effort: it never blocks startup.
func wireGlobalProjectRoleGrantsNotice(cw *coreWiring) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, line := range ssoRoleScopeWarnings(ctx, cw.core, cw.cfg) {
		log.Printf("WARNING: %s", line)
	}
	grants, err := cw.core.ListRoleGrantsOutsideAssignableScope(ctx)
	if err != nil {
		log.Printf("role grant scope check: %v (continuing; the check did not run)", err)
	} else {
		for _, line := range roleGrantsOutsideScopeNotice(grants) {
			log.Print(line)
		}
	}
	invs, err := cw.core.ListPendingInvitationsOutsideAssignableScope(ctx)
	if err != nil {
		log.Printf("pending invitation scope check: %v (continuing; the check did not run)", err)
	} else {
		for _, line := range invitationsOutsideScopeNotice(invs) {
			log.Print(line)
		}
	}
	envGrants, err := cw.core.ListEnvironmentWithoutProjectGrants(ctx)
	if err != nil {
		log.Printf("environment-without-project grant check: %v (continuing; the check did not run)", err)
		return nil
	}
	for _, line := range environmentWithoutProjectGrantNotice(envGrants) {
		log.Print(line)
	}
	return nil
}

// environmentWithoutProjectGrantNotice renders the startup notice for grants at
// {project_id: 0, environment_id: X} (ROLE-SHAPE-1, #2857); nil when there are
// none. Any role: unlike the assignable-scope notice below, the problem is the
// shape, which the access review of X's project does not list.
func environmentWithoutProjectGrantNotice(grants []core.EnvironmentWithoutProjectGrant) []string {
	if len(grants) == 0 {
		return nil
	}
	lines := []string{fmt.Sprintf("WARNING: %d existing role grant(s) at project_id=0 with an environment_id: each applies "+
		"inside that environment but is missing from its project's access review. New grants like these are refused "+
		"since #3546; these were left in place. Re-create each with the environment's project_id, then remove it:", len(grants))}
	for i, g := range grants {
		if i == maxGlobalProjectRoleGrantLines {
			lines = append(lines, fmt.Sprintf("WARNING:   ... and %d more (each project's access review names its own)", len(grants)-i))
			break
		}
		lines = append(lines, "WARNING:   "+g.Describe())
	}
	return lines
}

// roleGrantsOutsideScopeNotice renders the startup notice for grants; nil when
// there are none.
func roleGrantsOutsideScopeNotice(grants []core.RoleGrantOutsideScope) []string {
	if len(grants) == 0 {
		return nil
	}
	lines := []string{fmt.Sprintf("WARNING: %d existing grant(s) at a scope their role does not allow. A project "+
		"role held globally (no project) applies in EVERY project. New grants like these are refused since #3546; "+
		"these were left in place for review. For each, re-grant the role at the scope intended, then remove this "+
		"grant (DELETE /api/v1/user-roles, or DELETE /api/v1/groups/{id}/roles/{roleId} with the same project_id).", len(grants))}
	for i, g := range grants {
		if i == maxGlobalProjectRoleGrantLines {
			lines = append(lines, fmt.Sprintf("WARNING:   ... and %d more", len(grants)-i))
			break
		}
		where := "globally"
		if g.ProjectID != 0 {
			where = fmt.Sprintf("at project_id=%d", g.ProjectID)
		}
		detail := ""
		if g.EnvironmentID != 0 {
			detail += fmt.Sprintf(", environment_id=%d", g.EnvironmentID)
		}
		if g.ExpiresAt != nil {
			detail += ", expires " + g.ExpiresAt.UTC().Format(time.RFC3339)
		}
		lines = append(lines, fmt.Sprintf("WARNING:   %s %d holds %s %s%s (the role is %s-assignable)",
			g.PrincipalType, g.PrincipalID, g.RoleName, where, detail, g.AssignableScope))
	}
	return lines
}

// invitationsOutsideScopeNotice renders the notice for pending invitations
// that can no longer be accepted; nil when there are none.
func invitationsOutsideScopeNotice(invs []core.InvitationOutsideScope) []string {
	if len(invs) == 0 {
		return nil
	}
	lines := []string{fmt.Sprintf("WARNING: %d pending invitation(s) grant a role at a scope it does not allow, so "+
		"accepting them fails (#3546). Revoke each and send a new one with a valid role.", len(invs))}
	for i, inv := range invs {
		if i == maxGlobalProjectRoleGrantLines {
			lines = append(lines, fmt.Sprintf("WARNING:   ... and %d more", len(invs)-i))
			break
		}
		where := "globally"
		if inv.ProjectID != 0 {
			where = fmt.Sprintf("at project_id=%d", inv.ProjectID)
		}
		lines = append(lines, fmt.Sprintf("WARNING:   invitation %d grants %s %s", inv.InvitationID, inv.RoleName, where))
	}
	return lines
}

// globalRoleScopeResolver is the part of core the SSO check needs.
type globalRoleScopeResolver interface {
	RoleAssignableAtGlobalScopeByName(ctx context.Context, name string) (ok, found bool, err error)
}

// ssoRoleScopeWarnings names each SSO provider setting that maps a role which
// may not be granted globally: both default_role and group_role_map grant at
// the global scope, so such a mapping is refused at login. An unknown role or a
// failed lookup is not reported here (login reports it).
func ssoRoleScopeWarnings(ctx context.Context, roles globalRoleScopeResolver, cfg *config.Config) []string {
	projectOnly := func(name string) bool {
		ok, found, err := roles.RoleAssignableAtGlobalScopeByName(ctx, name)
		return err == nil && found && !ok
	}
	var out []string
	for _, p := range cfg.SSO.Providers {
		if role := strings.TrimSpace(p.DefaultRole); role != "" && projectOnly(role) {
			out = append(out, fmt.Sprintf("sso provider %q: default_role %s is a project role, which would apply in every project; "+
				"JIT provisioning through this provider is refused until default_role names a role assignable install-wide (e.g. system_viewer)", p.Name, role))
		}
		groups := make([]string, 0, len(p.GroupRoleMap))
		for group, role := range p.GroupRoleMap {
			if projectOnly(strings.TrimSpace(role)) {
				groups = append(groups, group)
			}
		}
		sort.Strings(groups)
		for _, group := range groups {
			out = append(out, fmt.Sprintf("sso provider %q: group_role_map %q -> %s maps a project role at the global scope; "+
				"the grant is refused at login. Use a Keyorix group with a project-scoped role grant instead",
				p.Name, group, strings.TrimSpace(p.GroupRoleMap[group])))
		}
	}
	return out
}
