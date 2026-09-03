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
	"errors"
	"fmt"
	"slices"
	"strings"
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
	return slices.Contains(membershipTransitions[from], to)
}

// SetMembershipValidationMode overrides the install validation mode (default
// ValidationModeAllowlist). The server calls this at startup from config.
func (c *KeyorixCore) SetMembershipValidationMode(mode string) {
	switch mode {
	case ValidationModeOpen, ValidationModeAllowlist, ValidationModeIDP:
		c.membershipValidationMode = mode
	}
}

// SetMembershipDomainAllowlist restricts InviteToProject/InviteGlobal to these
// email domains (ADR-022). Empty = no restriction. The server calls this at
// startup from config.
func (c *KeyorixCore) SetMembershipDomainAllowlist(domains []string) {
	c.membershipDomainAllowlist = domains
}

// domainAllowed reports whether email's domain passes the configured
// allowlist. An empty allowlist means no restriction (default, backward
// compatible).
//
// #G46: this used to extract the domain via strings.LastIndex(email, "@"),
// which silently accepts a malformed multi-'@' address like
// "attacker@evil.com@allowed.com" and reports its trailing segment as the
// domain — a parser-differential risk if any downstream mail/identity
// consumer of the same raw email string parses '@' differently (e.g. takes
// the FIRST '@' as the local-part boundary). Requiring exactly one '@' closes
// that gap: a malformed address is rejected outright instead of having its
// domain guessed.
func (c *KeyorixCore) domainAllowed(email string) bool {
	if len(c.membershipDomainAllowlist) == 0 {
		return true
	}
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return false
	}
	domain = strings.ToLower(domain)
	for _, d := range c.membershipDomainAllowlist {
		if strings.ToLower(d) == domain {
			return true
		}
	}
	return false
}

// domainAllowedForUser is domainAllowed for the userID-keyed onboarding paths
// (InviteMember, AddProjectMember, SetProjectMemberRole) — every place that
// grants a project-scope role directly by user ID rather than by email, and
// so doesn't otherwise pass through InviteToProject/InviteGlobal's check.
func (c *KeyorixCore) domainAllowedForUser(ctx context.Context, userID uint) error {
	if len(c.membershipDomainAllowlist) == 0 {
		return nil
	}
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if !c.domainAllowed(user.Email) {
		return fmt.Errorf("email domain is not on the allowlist")
	}
	return nil
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
func (c *KeyorixCore) InviteMember(ctx context.Context, projectID, userID uint, role string, invitedBy, invitedByMachineID uint, idpResolved bool) (*models.ProjectMembership, error) {
	return c.inviteMemberWithMode(ctx, projectID, userID, role, invitedBy, invitedByMachineID, c.validationMode(), idpResolved)
}

// inviteMemberWithMode is InviteMember with an explicit validation mode, so the
// invitation-accept flow (ADR-024/ADR-028) can honour the mode snapshotted at invite
// time rather than the install's current mode. InviteMember passes the current mode.
func (c *KeyorixCore) inviteMemberWithMode(ctx context.Context, projectID, userID uint, role string, invitedBy, invitedByMachineID uint, mode string, idpResolved bool) (*models.ProjectMembership, error) {
	if projectID == 0 || userID == 0 {
		return nil, fmt.Errorf("project and user IDs are required")
	}
	if role == "" {
		return nil, fmt.Errorf("a project role is required")
	}
	inviteMemberRole, err := c.storage.GetRoleByName(ctx, role)
	if err != nil {
		return nil, fmt.Errorf("unknown role %q: %w", role, err)
	}
	if err := c.domainAllowedForUser(ctx, userID); err != nil {
		return nil, err
	}
	// The parent project must be live. GetProject is soft-delete-scoped, so this refuses
	// onboarding into a soft-deleted project — otherwise accepting an invitation that was
	// outstanding when the project was deleted would re-establish a membership/role grant
	// that silently resurrects on a later RestoreProject (the restore-into-deleted-parent
	// class). It also covers the per-assignment grants applied at invite-accept.
	if _, err := c.storage.GetProject(ctx, projectID); err != nil {
		return nil, fmt.Errorf("project %d not found or deleted", projectID)
	}
	// Escalation-by-proxy guard: onboarding a member requires the inviter to already
	// hold every permission the role bundles (parallel to the access-request
	// approval ceiling), not merely an admin-tier role name. idpResolved invites
	// still pass through here.
	if err := c.requireGranterHoldsRolePermissions(ctx, invitedBy, inviteMemberRole.ID, Scope{ProjectID: projectID}, invitedByMachineID != 0); err != nil {
		return nil, err
	}
	// One active onboarding per (project, user).
	if existing, err := c.storage.GetActiveProjectMembership(ctx, projectID, userID); err == nil && existing != nil {
		return nil, fmt.Errorf("user already has a %s membership in this project", existing.State)
	}

	now := c.now()
	initial := initialMembershipStateForMode(mode, idpResolved)
	m := &models.ProjectMembership{
		ProjectID:                  projectID,
		UserID:                     userID,
		Role:                       role,
		State:                      initial,
		InvitedBy:                  invitedBy,
		InvitedByMachineIdentityID: invitedByMachineID,
		InvitedAt:                  now,
		UpdatedAt:                  now,
	}
	if initial == MembershipActive {
		t := now
		m.ActivatedAt = &t
	}
	created, err := c.storage.CreateProjectMembership(ctx, m)
	if err != nil {
		// #309: the "no active membership" read above races with a concurrent invite for
		// the same (project, user) — both can pass it before either commits. The DB-level
		// partial unique index (uniq_project_memberships_active) catches the loser's Create
		// and CreateProjectMembership wraps it in ErrDuplicateActiveMembership; surface the
		// same clean "already has a membership" error the winner's sequential check would
		// have produced, instead of a raw constraint-violation message or an orphaned row.
		return nil, wrapCreateMembershipError(err)
	}

	c.logMembershipEvent(ctx, "membership.invited", created, invitedBy)
	// If the mode put us straight into active, grant the role now.
	if created.State == MembershipActive {
		if err := c.AddProjectMember(ctx, invitedBy, projectID, userID, role, invitedByMachineID != 0); err != nil {
			// #309: created just committed as `active` above; if the role grant that's
			// supposed to back it fails (e.g. the composite user_roles primary key
			// rejects a grant that already exists via some other, independent path —
			// the DB-level uniq_project_memberships_active index only dedupes
			// ProjectMembership rows, not user_roles grants), leaving that row standing
			// would report a failure to the caller while a live active-looking
			// membership with no grant behind it persists in ListProjectMemberships/
			// ListUserProjectMemberships indefinitely. There's no earlier state to fall
			// back to (this row didn't exist before this call), so revert straight to
			// revoked.
			c.revertFailedActivation(ctx, created, MembershipRevoked)
			return nil, fmt.Errorf("failed to grant role on activation: %w", err)
		}
		c.logMembershipEvent(ctx, "membership.activated", created, invitedBy)
	}
	return created, nil
}

func wrapCreateMembershipError(err error) error {
	if errors.Is(err, storage.ErrDuplicateActiveMembership) {
		return fmt.Errorf("user already has a membership in this project")
	}
	return fmt.Errorf("failed to create membership: %w", err)
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
// actorIsMachine distinguishes a machine-credential-authenticated caller (also
// actorID==0) from the true actorID==0 system pseudo-actor.
func (c *KeyorixCore) TransitionMembership(ctx context.Context, projectID, membershipID uint, to string, actorID uint, actorIsMachine bool) (*models.ProjectMembership, error) {
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
	// applies: the actor must already hold every permission the membership's role
	// bundles to activate it. (Revocation/other transitions remove or don't grant, so
	// they're unaffected.)
	if to == MembershipActive {
		activateRole, err := c.storage.GetRoleByName(ctx, m.Role)
		if err != nil {
			return nil, fmt.Errorf("unknown role %q: %w", m.Role, err)
		}
		if err := c.requireGranterHoldsRolePermissions(ctx, actorID, activateRole.ID, Scope{ProjectID: m.ProjectID}, actorIsMachine); err != nil {
			return nil, err
		}
	}

	prevState := m.State
	now := c.now()
	m.State = to
	m.UpdatedAt = now
	switch to {
	case MembershipActive:
		m.ActivatedAt = &now
	case MembershipRevoked:
		m.RevokedAt = &now
	}
	// #G42: a blind UpdateProjectMembership (full-row Save) here would race a
	// concurrent TransitionMembership call on the same membership — m was
	// read above via GetProjectMembership with no lock, so a concurrent
	// transition landing between that read and this write would be silently
	// reverted (or, if this write lands first, silently clobbered). Route
	// through the conditional write gated on the state this call actually
	// observed (prevState).
	matched, err := c.storage.TransitionProjectMembershipState(ctx, m, prevState)
	if err != nil {
		return nil, fmt.Errorf("failed to update membership: %w", err)
	}
	if !matched {
		return nil, fmt.Errorf("membership %d: %w", membershipID, ErrMembershipStateConflict)
	}

	// Side effects on the role grant.
	switch to {
	case MembershipActive:
		if err := c.AddProjectMember(ctx, actorID, m.ProjectID, m.UserID, m.Role, actorIsMachine); err != nil {
			// #309: m just committed as `active` above; if the role grant fails, revert
			// to the state m held before this transition (not straight to revoked) —
			// unlike inviteMemberWithMode's straight-to-active create, this row already
			// existed in a legitimate pending state, so a failed activation attempt
			// should leave it retriable rather than terminally revoked. See
			// revertFailedActivation.
			c.revertFailedActivation(ctx, m, prevState)
			return nil, fmt.Errorf("failed to grant role on activation: %w", err)
		}
	case MembershipRevoked:
		if err := c.RemoveProjectMember(ctx, actorID, m.ProjectID, m.UserID); err != nil && !errors.Is(err, ErrNotProjectMember) {
			// #G54: a security-relevant refusal (guardLastProjectAdmin: this user is
			// the project's last roles.assign holder) or a real storage failure must
			// not be silently swallowed — the membership row was just committed as
			// `revoked` above, but if the underlying role grant removal was
			// REFUSED, the user still holds full access via that live grant while
			// ListProjectMemberships and friends report them as removed. Revert the
			// membership back to its pre-transition state and surface the error,
			// same as the activation-failure handling above. ErrNotProjectMember
			// (no grant existed to remove — already gone via some other path) is
			// the one genuinely benign case and is still ignored.
			c.revertFailedActivation(ctx, m, prevState)
			return nil, fmt.Errorf("failed to remove role grant on revocation: %w", err)
		}
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

// revertFailedActivation reverts a ProjectMembership row that was just persisted as
// `active` back to a non-active state, after the role grant that's supposed to back
// that `active` row failed (#309). Without this, a caller-visible error ("failed to
// grant role on activation") would still leave a live state=active row behind —
// ListProjectMemberships/ListUserProjectMemberships would keep reporting the user as
// an active project member indefinitely, with no role grant behind it and no way to
// revoke a grant that was never made. This can happen without any TOCTOU: the
// uniq_project_memberships_active partial index only dedupes ProjectMembership rows,
// not user_roles grants, so a role already held via an independent path (a direct
// /user-roles grant, another membership's activation, etc.) still makes
// AssignRole's composite primary key reject this grant after the row committed.
//
// toState is the state to fall back to: inviteMemberWithMode has no earlier state to
// return to (the row didn't exist before this call) and passes MembershipRevoked;
// TransitionMembership passes the membership's own pre-transition state, so a
// legitimate retry of the activation is still possible.
//
// Best-effort and mirrors revokeInvitationGrants (invitations.go): m is already on a
// path that's about to return an error to its caller, so a failure to revert is
// audited (flagged for manual cleanup) rather than returned or retried — a partial
// revert is strictly better than silently leaving the active row standing.
func (c *KeyorixCore) revertFailedActivation(ctx context.Context, m *models.ProjectMembership, toState string) {
	// #G42: m.State is still MembershipActive here (TransitionMembership's own
	// write above just committed it) — capture that as fromState so this
	// revert's write only matches if nothing else has touched the row since,
	// same as TransitionMembership's own conditional write.
	fromState := m.State
	m.State = toState
	m.UpdatedAt = c.now()
	if toState == MembershipRevoked {
		t := c.now()
		m.RevokedAt = &t
	} else {
		m.ActivatedAt = nil
	}
	matched, err := c.storage.TransitionProjectMembershipState(ctx, m, fromState)
	if err == nil && !matched {
		err = fmt.Errorf("%w", ErrMembershipStateConflict)
	}
	if err != nil {
		c.auditProjectScoped(ctx, "membership.activation_race_revert_failed", m.UserID, m.ProjectID,
			fmt.Sprintf("failed to revert orphaned active membership %d for user %d in project %d (state %s) after a role-grant failure: %v — MANUAL CLEANUP REQUIRED",
				m.ID, m.UserID, m.ProjectID, toState, err))
		return
	}
	c.logMembershipEvent(ctx, "membership.activation_reverted", m, 0)
}
