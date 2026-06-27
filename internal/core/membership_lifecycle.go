// membership_lifecycle.go — project membership onboarding state machine (ADR-022).
//
// A ProjectMembership tracks a user's onboarding into a project, separate from
// the role grant (user_roles). The lifecycle is a 5-state machine:
//
//	invited → identity_verified → provisioned → active   (revoked is terminal,
//	                                                       reachable from any
//	                                                       non-terminal state)
//
// The actual project role is granted (via AssignRole) only when a membership
// reaches `active`, and removed when it is revoked. An install's validation mode
// controls how much of the chain a new invite must traverse:
//
//	open      — self-serve: an invite lands directly in `active`.
//	allowlist — an admin steps the membership through each state explicitly.
//	idp       — IdP-resolved users skip invited/identity_verified (provisioned),
//	            others start at `invited`.
//
// Every transition writes a discrete audit event. Email/setup-link delivery
// (ADR-024) and inviter notifications are separate follow-ups.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Membership states.
const (
	MembershipInvited          = "invited"
	MembershipIdentityVerified = "identity_verified"
	MembershipProvisioned      = "provisioned"
	MembershipActive           = "active"
	MembershipRevoked          = "revoked"
)

// Validation modes (install-level).
const (
	ValidationModeOpen      = "open"
	ValidationModeAllowlist = "allowlist"
	ValidationModeIDP       = "idp"
)

// membershipTransitions lists the allowed next states for each state. revoked is
// terminal (no outgoing transitions); every non-terminal state may go to revoked.
var membershipTransitions = map[string][]string{
	MembershipInvited:          {MembershipIdentityVerified, MembershipRevoked},
	MembershipIdentityVerified: {MembershipProvisioned, MembershipRevoked},
	MembershipProvisioned:      {MembershipActive, MembershipRevoked},
	MembershipActive:           {MembershipRevoked},
	MembershipRevoked:          {},
}

// canTransition reports whether a membership may move from → to.
func canTransition(from, to string) bool {
	for _, next := range membershipTransitions[from] {
		if next == to {
			return true
		}
	}
	return false
}

// SetMembershipValidationMode overrides the install validation mode (default
// ValidationModeAllowlist). The server calls this at startup from config.
func (c *KeyorixCore) SetMembershipValidationMode(mode string) {
	switch mode {
	case ValidationModeOpen, ValidationModeAllowlist, ValidationModeIDP:
		c.membershipValidationMode = mode
	}
}

func (c *KeyorixCore) validationMode() string {
	if c.membershipValidationMode == "" {
		return ValidationModeAllowlist
	}
	return c.membershipValidationMode
}

// InviteMember starts a membership for userID in projectID with the given
// intended role. The initial state depends on the install validation mode (and,
// for idp, whether the user is IdP-resolved). Rejects a duplicate non-revoked
// membership. When the mode lands the membership directly in `active`, the role
// grant is applied immediately.
func (c *KeyorixCore) InviteMember(ctx context.Context, projectID, userID uint, role string, invitedBy uint, idpResolved bool) (*models.ProjectMembership, error) {
	return c.inviteMemberWithMode(ctx, projectID, userID, role, invitedBy, c.validationMode(), idpResolved)
}

// inviteMemberWithMode is InviteMember with an explicit validation mode, so the
// invitation-accept flow (ADR-024/ADR-028) can honour the mode snapshotted at invite
// time rather than the install's current mode. InviteMember passes the current mode.
func (c *KeyorixCore) inviteMemberWithMode(ctx context.Context, projectID, userID uint, role string, invitedBy uint, mode string, idpResolved bool) (*models.ProjectMembership, error) {
	if projectID == 0 || userID == 0 {
		return nil, fmt.Errorf("project and user IDs are required")
	}
	if role == "" {
		return nil, fmt.Errorf("a project role is required")
	}
	if _, err := c.storage.GetRoleByName(ctx, role); err != nil {
		return nil, fmt.Errorf("unknown role %q: %w", role, err)
	}
	// The parent project must be live. GetProject is soft-delete-scoped, so this refuses
	// onboarding into a soft-deleted project — otherwise accepting an invitation that was
	// outstanding when the project was deleted would re-establish a membership/role grant
	// that silently resurrects on a later RestoreProject (the restore-into-deleted-parent
	// class). It also covers the per-assignment grants applied at invite-accept.
	if _, err := c.storage.GetProject(ctx, projectID); err != nil {
		return nil, fmt.Errorf("project %d not found or deleted", projectID)
	}
	// Escalation-by-proxy guard: onboarding a member as an admin role requires the
	// inviter to hold admin authority at the project (parallel to the access-request
	// approval ceiling). idpResolved invites still pass through here.
	if err := c.requireAuthorityForRole(ctx, invitedBy, projectID, role); err != nil {
		return nil, err
	}
	// One active onboarding per (project, user).
	if existing, err := c.storage.GetActiveProjectMembership(ctx, projectID, userID); err == nil && existing != nil {
		return nil, fmt.Errorf("user already has a %s membership in this project", existing.State)
	}

	now := c.now()
	initial := initialMembershipStateForMode(mode, idpResolved)
	m := &models.ProjectMembership{
		ProjectID: projectID,
		UserID:    userID,
		Role:      role,
		State:     initial,
		InvitedBy: invitedBy,
		InvitedAt: now,
		UpdatedAt: now,
	}
	if initial == MembershipActive {
		t := now
		m.ActivatedAt = &t
	}
	created, err := c.storage.CreateProjectMembership(ctx, m)
	if err != nil {
		return nil, fmt.Errorf("failed to create membership: %w", err)
	}

	// If the mode put us straight into active, grant the role now.
	if created.State == MembershipActive {
		if err := c.AddProjectMember(ctx, projectID, userID, role); err != nil {
			return nil, fmt.Errorf("failed to grant role on activation: %w", err)
		}
	}
	c.logMembershipEvent(ctx, "membership.invited", created, invitedBy)
	if created.State == MembershipActive {
		c.logMembershipEvent(ctx, "membership.activated", created, invitedBy)
	}
	return created, nil
}

// initialMembershipStateForMode resolves the starting state for a new invite under
// an explicit validation mode. An empty/unknown mode falls back to allowlist.
func initialMembershipStateForMode(mode string, idpResolved bool) string {
	switch mode {
	case ValidationModeOpen:
		return MembershipActive
	case ValidationModeIDP:
		if idpResolved {
			return MembershipProvisioned // skip invited/identity_verified
		}
		return MembershipInvited
	default: // allowlist (and empty/unknown)
		return MembershipInvited
	}
}

// TransitionMembership advances a membership to the next state, enforcing the
// state machine. Reaching `active` grants the project role; `revoked` removes it.
// actorID is the user performing the transition (for the audit trail).
func (c *KeyorixCore) TransitionMembership(ctx context.Context, projectID, membershipID uint, to string, actorID uint) (*models.ProjectMembership, error) {
	m, err := c.storage.GetProjectMembership(ctx, membershipID)
	if err != nil {
		return nil, fmt.Errorf("membership not found")
	}
	// The caller is authorized within projectID; a membership in another project
	// must not be reachable through it (cross-project guard).
	if m.ProjectID != projectID {
		return nil, fmt.Errorf("membership not found")
	}
	if !canTransition(m.State, to) {
		return nil, fmt.Errorf("cannot transition membership from %s to %s", m.State, to)
	}
	// Activating a membership grants its role, so the same escalation-by-proxy ceiling
	// applies: the actor must hold admin authority at the project to activate a membership
	// carrying an admin role. (Revocation/other transitions remove or don't grant, so
	// they're unaffected.)
	if to == MembershipActive {
		if err := c.requireAuthorityForRole(ctx, actorID, m.ProjectID, m.Role); err != nil {
			return nil, err
		}
	}

	now := c.now()
	m.State = to
	m.UpdatedAt = now
	switch to {
	case MembershipActive:
		m.ActivatedAt = &now
	case MembershipRevoked:
		m.RevokedAt = &now
	}
	if err := c.storage.UpdateProjectMembership(ctx, m); err != nil {
		return nil, fmt.Errorf("failed to update membership: %w", err)
	}

	// Side effects on the role grant.
	switch to {
	case MembershipActive:
		if err := c.AddProjectMember(ctx, m.ProjectID, m.UserID, m.Role); err != nil {
			return nil, fmt.Errorf("failed to grant role on activation: %w", err)
		}
	case MembershipRevoked:
		// Best-effort: the membership is already revoked; a missing grant is fine.
		_ = c.RemoveProjectMember(ctx, m.ProjectID, m.UserID)
	}

	c.logMembershipEvent(ctx, "membership."+transitionVerb(to), m, actorID)
	if to == MembershipActive {
		c.notifyMembershipActivated(ctx, m)
	}
	return m, nil
}

// (helpers below)

// transitionVerb maps a target state to the audit event suffix.
func transitionVerb(to string) string {
	switch to {
	case MembershipIdentityVerified:
		return "identity_verified"
	case MembershipProvisioned:
		return "provisioned"
	case MembershipActive:
		return "activated"
	case MembershipRevoked:
		return "revoked"
	default:
		return to
	}
}

// ListProjectMemberships returns all membership rows for a project.
func (c *KeyorixCore) ListProjectMemberships(ctx context.Context, projectID uint) ([]*models.ProjectMembership, error) {
	return c.storage.ListProjectMemberships(ctx, projectID)
}

// StaleInvites returns memberships still in `invited` state older than the cutoff
// (ADR-022 stale-invite warnings; default surfaced at >7 days).
func (c *KeyorixCore) StaleInvites(ctx context.Context, olderThan time.Duration) ([]*models.ProjectMembership, error) {
	before := c.now().Add(-olderThan)
	return c.storage.ListStaleInvitedMemberships(ctx, before)
}

// ListUserProjectMemberships returns all membership rows for a single user
// (ADR-025 per-user assignments view).
func (c *KeyorixCore) ListUserProjectMemberships(ctx context.Context, userID uint) ([]*models.ProjectMembership, error) {
	return c.storage.ListUserProjectMemberships(ctx, userID)
}

// ProjectMembershipCounts returns per-user project-membership tallies (active and
// non-revoked total) for the given user IDs in one query (ADR-025 user list).
func (c *KeyorixCore) ProjectMembershipCounts(ctx context.Context, userIDs []uint) (map[uint]storage.MembershipCounts, error) {
	return c.storage.CountProjectMembershipsByUsers(ctx, userIDs)
}

// logMembershipEvent writes an audit event for a membership transition.
func (c *KeyorixCore) logMembershipEvent(ctx context.Context, eventType string, m *models.ProjectMembership, actorID uint) {
	aid, pid := actorID, m.ProjectID
	c.writeAuditEventFull(ctx, eventType, &aid, nil, &pid, "",
		fmt.Sprintf("membership %d for user %d in project %d → %s", m.ID, m.UserID, m.ProjectID, m.State))
}
