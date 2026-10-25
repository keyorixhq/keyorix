// global_project_role_grants.go — GROUP-ROLE-SCOPE-1 (#3546): the read-only
// report of grants the role-scope guard (role_scope_guard.go) now refuses but
// that already exist: a role held at a scope its AssignableScope does not
// allow. The case that matters is a project-assignable role at the global
// scope, which applies in every project; the reverse (a global-assignable role
// at a project) is listed too (#3554 review follow-up 4). Nothing here deletes
// or changes a grant: some may be relied on, so they need a human's review.
package core

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// RoleGrantOutsideScope is one existing user or group grant at a scope its
// role's assignable scope does not allow.
type RoleGrantOutsideScope struct {
	PrincipalType   string // "user" or "group"
	PrincipalID     uint
	RoleName        string
	AssignableScope string // the role's: project (held globally) or global (held at a project)
	ProjectID       uint
	EnvironmentID   uint       // non-zero with ProjectID 0: the {0, X} shape, also refused now
	ExpiresAt       *time.Time // nil = permanent
}

// ListRoleGrantsOutsideAssignableScope returns every user and group grant the
// role-scope check would refuse as a new grant on its role and scope alone
// (validateRoleScope; environment existence is not re-checked), expired
// time-bound rows included (the sweep may not have run yet), sorted by
// principal type, principal ID, then role. Read-only.
func (c *KeyorixCore) ListRoleGrantsOutsideAssignableScope(ctx context.Context) ([]RoleGrantOutsideScope, error) {
	roles, err := c.storage.ListRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	byID := make(map[uint]*models.Role, len(roles))
	for _, r := range roles {
		byID[r.ID] = r
	}
	var out []RoleGrantOutsideScope
	add := func(principalType string, principalID, roleID uint, scope Scope, expiresAt *time.Time) {
		r, ok := byID[roleID]
		if !ok || validateRoleScope(r, scope) == nil {
			return
		}
		out = append(out, RoleGrantOutsideScope{PrincipalType: principalType, PrincipalID: principalID,
			RoleName: r.Name, AssignableScope: roleAssignableScope(r), ProjectID: scope.ProjectID,
			EnvironmentID: scope.EnvironmentID, ExpiresAt: expiresAt})
	}
	userGrants, err := c.storage.ListAllUserRoleGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, g := range userGrants {
		add("user", g.UserID, g.RoleID, Scope{ProjectID: g.ProjectID, EnvironmentID: g.EnvironmentID}, g.ExpiresAt)
	}
	groupGrants, err := c.storage.ListAllGroupRoleGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, g := range groupGrants {
		add("group", g.GroupID, g.RoleID, Scope{ProjectID: g.ProjectID, EnvironmentID: g.EnvironmentID}, g.ExpiresAt)
	}
	slices.SortFunc(out, func(a, b RoleGrantOutsideScope) int {
		return cmp.Or(cmp.Compare(a.PrincipalType, b.PrincipalType), cmp.Compare(a.PrincipalID, b.PrincipalID),
			cmp.Compare(a.RoleName, b.RoleName), cmp.Compare(a.ProjectID, b.ProjectID))
	})
	return out, nil
}

// InvitationOutsideScope is a pending invitation one of whose grants the
// role-scope check refuses, so accepting it fails (#3554 review follow-up 2).
type InvitationOutsideScope struct {
	InvitationID uint
	Email        string
	RoleName     string
	ProjectID    uint // the grant's: 0 = the invitation's global system role
}

// ListPendingInvitationsOutsideAssignableScope returns the pending invitations
// (global and per project) that can no longer be accepted because of their
// role's assignable scope, sorted by invitation ID. Read-only.
func (c *KeyorixCore) ListPendingInvitationsOutsideAssignableScope(ctx context.Context) ([]InvitationOutsideScope, error) {
	projects, err := c.storage.ListProjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	projectIDs := []uint{0} // global invitations
	for _, p := range projects {
		projectIDs = append(projectIDs, p.ID)
	}
	var out []InvitationOutsideScope
	for _, pid := range projectIDs {
		invs, err := c.storage.ListProjectInvitations(ctx, pid)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		for _, inv := range invs {
			if inv.State != InvitationPending {
				continue
			}
			grants, err := invitationGrantScopes(inv)
			if err != nil {
				continue // undecodable: accept reports it, as it always has
			}
			for _, g := range grants {
				r, err := c.storage.GetRoleByName(ctx, g.role)
				if err != nil || validateRoleScope(r, g.scope) == nil {
					continue
				}
				out = append(out, InvitationOutsideScope{InvitationID: inv.ID, Email: inv.Email, RoleName: r.Name, ProjectID: g.scope.ProjectID})
				break
			}
		}
	}
	slices.SortFunc(out, func(a, b InvitationOutsideScope) int { return cmp.Compare(a.InvitationID, b.InvitationID) })
	return out, nil
}

// RoleAssignableAtGlobalScopeByName resolves name and reports whether it may
// be granted with no project. found is false when no such role exists.
func (c *KeyorixCore) RoleAssignableAtGlobalScopeByName(ctx context.Context, name string) (ok, found bool, err error) {
	r, err := c.storage.GetRoleByName(ctx, name)
	if err != nil {
		if errors.Is(err, storage.ErrRoleNotFound) {
			return false, false, nil
		}
		return false, false, err
	}
	return RoleAssignableAtGlobalScope(r), true, nil
}
