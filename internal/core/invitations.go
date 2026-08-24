// invitations.go — project invitations + access requests (ADR-024).
//
// Two related onboarding flows:
//
//   - Invitations: an admin invites an email to a project with an intended role.
//     State: pending → accepted / revoked / expired. The email/setup-link
//     consumption (accept) is implemented in setup_consume.go
//     (completeInvitationAccept); this tracks the pending invite so it can be
//     listed, revoked, and aged out.
//   - Access requests: a user asks for a role in a project. State: pending →
//     approved / rejected / withdrawn / expired. Approval grants the (possibly
//     adjusted) role at the project scope. No auto-approval.
//
// Every transition is audited. TTLs: invitations 14 days, access requests 7 days.
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Invitation states.
const (
	InvitationPending  = "pending"
	InvitationAccepted = "accepted"
	InvitationRevoked  = "revoked"
	InvitationExpired  = "expired"
)

// Access request states.
const (
	AccessRequestPending   = "pending"
	AccessRequestApproved  = "approved"
	AccessRequestRejected  = "rejected"
	AccessRequestWithdrawn = "withdrawn"
	AccessRequestExpired   = "expired"
)

// TTLs (ADR-024).
const (
	invitationTTL    = 14 * 24 * time.Hour
	accessRequestTTL = 7 * 24 * time.Hour

	eventInvitationRaceRevokeFailed = "invitation.accept_race_revoke_failed" // #nosec G101 -- audit event type, not a credential
)

// ── Invitations ────────────────────────────────────────────────────────────

// requireAuthorityForRole refuses to GRANT an admin role (super_admin/admin/system_admin/
// project_admin) unless the actor holds admin authority at the project scope. The various
// grant entry points (access-request approval, project invite, membership activation) are
// gated by roles.assign, but that alone would let a non-admin roles.assign holder mint a
// principal more powerful than themselves — escalation-by-proxy. Non-admin roles pass (the
// roles.assign gate covers them). actorID==0 (a system/unauthenticated path) cannot grant
// an admin role through these flows.
func (c *KeyorixCore) requireAuthorityForRole(ctx context.Context, actorID, projectID uint, role string) error {
	if !isAdminRoleName(role) {
		return nil
	}
	if err := c.requireAdminAuthorityAt(ctx, actorID, projectID); err != nil {
		return fmt.Errorf("only an administrator can grant the administrative role %q: %w", role, err)
	}
	return nil
}

// RequireAdminAuthorityAt exports requireAdminAuthorityAt for the /system proxy
// layer (server/http/handlers), which cannot call unexported KeyorixCore methods
// across the package boundary. Used to re-derive, at the hub, the SAME ceiling
// core methods already enforce locally on a downstream node before relaying a
// state change here -- the #1542 shape, closed the same way
// TransitionMachineIdentityStateProxy's core.IsValidMachineTransition
// re-derivation was.
func (c *KeyorixCore) RequireAdminAuthorityAt(ctx context.Context, actorID, projectID uint) error {
	return c.requireAdminAuthorityAt(ctx, actorID, projectID)
}

// RequireAuthorityForRole exports requireAuthorityForRole for the same reason as
// RequireAdminAuthorityAt above.
func (c *KeyorixCore) RequireAuthorityForRole(ctx context.Context, actorID, projectID uint, role string) error {
	return c.requireAuthorityForRole(ctx, actorID, projectID, role)
}

// requireAdminAuthorityAt refuses unless actorID holds an admin role (adminRoleNames)
// directly assigned at the given project scope (0 = global). The shared primitive
// behind requireAuthorityForRole (gating a role GRANT) and any other action that
// carries equivalent risk without being a role grant per se — e.g. binding a
// rotation backend to a secret (#90): the backend often carries org-wide admin
// credentials, so the same escalation-by-proxy ceiling applies.
func (c *KeyorixCore) requireAdminAuthorityAt(ctx context.Context, actorID, projectID uint) error {
	ids, err := c.scopedRoleIDs(ctx, actorID, storage.Scope{ProjectID: projectID})
	if err != nil {
		return fmt.Errorf("failed to resolve actor authority: %w", err)
	}
	containsAdmin, err := c.roleSetContainsAdmin(ctx, ids)
	if err != nil {
		return fmt.Errorf("failed to resolve actor authority: %w", err)
	}
	if !containsAdmin {
		return fmt.Errorf("admin authority is required")
	}
	return nil
}

// InviteToProject creates a pending invitation for an email to a project with an
// intended role. It snapshots the current validation mode and sets a 14-day TTL.
func (c *KeyorixCore) InviteToProject(ctx context.Context, projectID uint, email, role string, invitedBy uint) (*models.ProjectInvitation, error) {
	if projectID == 0 || email == "" || role == "" {
		return nil, fmt.Errorf("project ID, email, and role are required")
	}
	if !c.domainAllowed(email) {
		return nil, fmt.Errorf("email domain is not on the allowlist")
	}
	if _, err := c.storage.GetRoleByName(ctx, role); err != nil {
		return nil, fmt.Errorf("unknown role %q: %w", role, err)
	}
	// Escalation-by-proxy guard: inviting someone as an admin role requires the inviter
	// to hold admin authority at the project (parallel to the access-request ceiling).
	if err := c.requireAuthorityForRole(ctx, invitedBy, projectID, role); err != nil {
		return nil, err
	}
	now := c.now()
	expires := now.Add(invitationTTL)
	inv := &models.ProjectInvitation{
		ProjectID: projectID,
		Email:     email,
		Role:      role,
		State:     InvitationPending,
		InvitedBy: invitedBy,
		// Snapshot the install validation mode (ADR-022) so acceptance honours the
		// mode in force at invite time, not whatever it changes to later.
		ValidationModeAtInvite: c.validationMode(),
		ExpiresAt:              &expires,
		CreatedAt:              now,
	}
	created, err := c.storage.CreateProjectInvitation(ctx, inv)
	if err != nil {
		return nil, fmt.Errorf("failed to create invitation: %w", err)
	}
	c.auditProjectScoped(ctx, "invitation.created", invitedBy, projectID,
		fmt.Sprintf("invited %s to project %d as %s", email, projectID, role))
	return created, nil
}

// InviteToProjectWithLink creates an invitation and provisions its accept link
// (ADR-028): an invitation_accept setup token bound to the invitation, delivered via
// the configured channel. Returns the invitation and the delivery outcome. If
// provisioning fails (e.g. base_url unset, or the resend throttle below), the
// invitation still exists and is returned with a nil result and the error, so the
// caller can resend rather than losing the invite.
//
// The link provisioning is throttled per (purpose, email) via
// provisionSetupLinkThrottled — the same control ResendInvitationLink uses (#183) —
// rather than the unthrottled provisionSetupLink an earlier version called directly.
// Without this, a principal holding only project-scoped roles.assign could loop-call
// this endpoint for the same target email to fire unbounded real SMTP sends from the
// operator's mail relay (#345); reusing the existing (purpose, email) key rather than
// adding an actor or per-invitation dimension keeps initial invites and resends of the
// same target subject to one combined rate, matching how ResendInvitationLink already
// treats every pending invite to the same email as one throttled subject.
//
// The SEPARATE pre-issuance supersede (IssueSetupToken's "kill the old link" step) is,
// unlike the throttle above, scoped to THIS project via SupersedeProjectID
// (CORE-INVITATIONS-003): without it, any admin holding roles.assign in some unrelated
// project B could invite the same target email to project B and, as a side effect,
// silently invalidate project A's still-pending invite link — a cross-project
// interference project B's admin has no authority to cause and no visibility into.
// Scoping the supersede (but deliberately NOT the throttle, which stays per (purpose,
// email) globally — see above) preserves the SMTP-abuse ceiling while eliminating that
// cross-project side effect. A genuine same-project resend/re-invite still supersedes
// the prior pending invite for that project, exactly as before.
func (c *KeyorixCore) InviteToProjectWithLink(ctx context.Context, projectID uint, email, role string, invitedBy uint) (*models.ProjectInvitation, *ProvisionSetupResult, error) {
	inv, err := c.InviteToProject(ctx, projectID, email, role, invitedBy)
	if err != nil {
		return nil, nil, err
	}
	prov, err := c.provisionSetupLinkThrottled(ctx, IssueSetupTokenRequest{
		Purpose:            SetupPurposeInvitationAccept,
		SubjectEmail:       email,
		InvitationID:       &inv.ID,
		CreatedBy:          invitedBy,
		SupersedeProjectID: &projectID,
	}, "", fmt.Sprintf("%s on project %d", role, projectID))
	if err != nil {
		return inv, nil, err
	}
	return inv, prov, nil
}

// InviteGlobal creates a non-project-scoped invitation (ProjectID 0) that, on
// accept, grants a system role plus a set of project assignments in one go — the
// invitation analogue of CreateUserWithAssignments (ADR-024/028). The system role
// and every assignment (project + role) are validated and deduped up front, so
// acceptance can't later fail on an unknown role or project. The per-project
// grants are snapshotted as JSON on the invitation.
func (c *KeyorixCore) InviteGlobal(ctx context.Context, email, systemRole string, assignments []ProjectAssignment, invitedBy uint) (*models.ProjectInvitation, error) { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if !c.domainAllowed(email) {
		return nil, fmt.Errorf("email domain is not on the allowlist")
	}
	sysRole := systemRole
	if sysRole == "" {
		sysRole = "system_viewer"
	}
	if _, err := c.storage.GetRoleByName(ctx, sysRole); err != nil {
		return nil, fmt.Errorf("unknown role %q (system): %w", sysRole, err)
	}
	// Escalation-by-proxy guard (#231), mirroring InviteToProject: a global system
	// role is the most powerful grant this flow can mint, so it needs the same
	// admin-authority ceiling check, at global scope (projectID 0).
	if err := c.requireAuthorityForRole(ctx, invitedBy, 0, sysRole); err != nil {
		return nil, err
	}

	// Validate + dedup assignments before persisting anything.
	seen := map[uint]bool{}
	clean := make([]ProjectAssignment, 0, len(assignments))
	for _, a := range assignments {
		if a.ProjectID == 0 || a.Role == "" {
			return nil, fmt.Errorf("each project assignment needs a project_id and a role")
		}
		if seen[a.ProjectID] {
			continue
		}
		seen[a.ProjectID] = true
		if _, err := c.storage.GetProject(ctx, a.ProjectID); err != nil {
			return nil, fmt.Errorf("unknown project %d: %w", a.ProjectID, err)
		}
		if _, err := c.storage.GetRoleByName(ctx, a.Role); err != nil {
			return nil, fmt.Errorf("unknown role %q: %w", a.Role, err)
		}
		// Same ceiling check InviteToProject applies to its own role parameter —
		// without this, a non-admin roles.assign holder could bundle an
		// admin-conferring project assignment into an otherwise-innocuous global
		// invite.
		if err := c.requireAuthorityForRole(ctx, invitedBy, a.ProjectID, a.Role); err != nil {
			return nil, err
		}
		clean = append(clean, ProjectAssignment{ProjectID: a.ProjectID, Role: a.Role})
	}
	assignJSON := ""
	if len(clean) > 0 {
		b, err := json.Marshal(clean)
		if err != nil {
			return nil, fmt.Errorf("failed to encode assignments: %w", err)
		}
		assignJSON = string(b)
	}

	now := c.now()
	expires := now.Add(invitationTTL)
	inv := &models.ProjectInvitation{
		ProjectID:              0, // global
		Email:                  email,
		Role:                   "",
		State:                  InvitationPending,
		InvitedBy:              invitedBy,
		SystemRole:             sysRole,
		AssignmentsJSON:        assignJSON,
		ValidationModeAtInvite: c.validationMode(),
		ExpiresAt:              &expires,
		CreatedAt:              now,
	}
	created, err := c.storage.CreateProjectInvitation(ctx, inv)
	if err != nil {
		return nil, fmt.Errorf("failed to create invitation: %w", err)
	}
	c.auditProjectScoped(ctx, "invitation.created", invitedBy, 0,
		fmt.Sprintf("invited %s globally as %s with %d project assignment(s)", email, sysRole, len(clean)))
	return created, nil
}

// InviteGlobalWithLink creates a global invitation and provisions its accept link
// (ADR-028), mirroring InviteToProjectWithLink. A nil result with a non-nil error
// and a non-nil invitation means the invite exists but the link couldn't be
// delivered (e.g. base_url unset, or the resend throttle) — the caller can resend.
// Throttled per (purpose, email) via provisionSetupLinkThrottled for the same reason
// as InviteToProjectWithLink (#345): the users.write-gated global-invite endpoint is
// otherwise an equally loop-callable unbounded-SMTP vector.
//
// Unlike InviteToProjectWithLink, SupersedeProjectID is intentionally left nil: a
// global invite (ProjectID 0) has no single project to scope the pre-issuance
// supersede to, so it keeps the original (purpose, email)-only scope — it still
// supersedes a prior pending global invite to the same address, and, as before, a
// prior PROJECT-scoped invite to that address (there is no narrower boundary to draw
// here; CORE-INVITATIONS-003 is specifically about project-vs-project interference).
func (c *KeyorixCore) InviteGlobalWithLink(ctx context.Context, email, systemRole string, assignments []ProjectAssignment, invitedBy uint) (*models.ProjectInvitation, *ProvisionSetupResult, error) {
	inv, err := c.InviteGlobal(ctx, email, systemRole, assignments, invitedBy)
	if err != nil {
		return nil, nil, err
	}
	prov, err := c.provisionSetupLinkThrottled(ctx, IssueSetupTokenRequest{
		Purpose:      SetupPurposeInvitationAccept,
		SubjectEmail: email,
		InvitationID: &inv.ID,
		CreatedBy:    invitedBy,
	}, "", fmt.Sprintf("%s + %d project assignment(s)", inv.SystemRole, len(assignments)))
	if err != nil {
		return inv, nil, err
	}
	return inv, prov, nil
}

// applyInvitationGrants materializes an invitation's role grants onto a freshly
// created (accepting) user. A global invite (ADR-024) grants its system role plus
// each project assignment from AssignmentsJSON; a project-scoped invite grants the
// single project role. Everything was validated at invite time, so a failure here
// is a storage error (leaving the invitation pending/resendable), not bad input.
func (c *KeyorixCore) applyInvitationGrants(ctx context.Context, inv *models.ProjectInvitation, userID uint) error { // NOSONAR -- cognitive complexity 22, suppress go:S3776
	// Global invite: system role + multi-project assignments.
	if inv.SystemRole != "" || inv.AssignmentsJSON != "" {
		if inv.SystemRole != "" {
			role, err := c.storage.GetRoleByName(ctx, inv.SystemRole)
			if err != nil {
				return fmt.Errorf("unknown system role %q: %w", inv.SystemRole, err)
			}
			// Routed through the audited wrapper — this is the moment of privilege
			// grant for a global invitation (up to and including super_admin), which
			// previously left zero trace of any kind (#299). Attributed to the inviter,
			// consistent with the per-project assignment grants below.
			if err := c.AssignUserRole(ctx, inv.InvitedBy, userID, role.ID, Scope{ProjectID: 0}); err != nil {
				return fmt.Errorf("failed to grant system role: %w", err)
			}
		}
		if inv.AssignmentsJSON != "" {
			var assignments []ProjectAssignment
			if err := json.Unmarshal([]byte(inv.AssignmentsJSON), &assignments); err != nil {
				return fmt.Errorf("failed to decode assignments: %w", err)
			}
			for _, a := range assignments {
				if _, err := c.inviteMemberWithMode(ctx, a.ProjectID, userID, a.Role, inv.InvitedBy, inv.ValidationModeAtInvite, false); err != nil {
					return err
				}
			}
		}
		return nil
	}
	// Project-scoped invite: single project membership.
	_, err := c.inviteMemberWithMode(ctx, inv.ProjectID, userID, inv.Role, inv.InvitedBy, inv.ValidationModeAtInvite, false)
	return err
}

// revokeInvitationGrants best-effort undoes applyInvitationGrants for userID. Used
// exclusively by completeInvitationAccept when it discovers, only after granting,
// that the invitation was concurrently revoked (#412): the conditional
// UpdateProjectInvitation write that would flip the row to accepted lost the race,
// so whatever was just granted must not be left standing behind an invitation that
// no longer reads as accepted. actorID 0 attributes the reversal to the system
// (mirroring applyInvitationGrants' own actorID-0-eligible AssignUserRole/
// inviteMemberWithMode calls), and every removal is independently best-effort — a
// failure on one project assignment must not stop the others from being reverted.
// Errors are audited, not returned or retried: the caller is already on a fail-closed
// path and a partial rollback is strictly better than leaving every grant live.
func (c *KeyorixCore) revokeInvitationGrants(ctx context.Context, inv *models.ProjectInvitation, userID uint) {
	if inv.SystemRole != "" || inv.AssignmentsJSON != "" {
		c.revokeSystemRoleGrant(ctx, inv, userID)
		c.revokeAssignmentGrants(ctx, inv, userID)
		return
	}
	// Project-scoped invite: revert the single project membership/role.
	if err := c.RemoveProjectMember(ctx, 0, inv.ProjectID, userID); err != nil {
		c.auditProjectScoped(ctx, eventInvitationRaceRevokeFailed, userID, inv.ProjectID,
			fmt.Sprintf("failed to revert project role %q granted to user %d by invitation %d: %v — MANUAL CLEANUP REQUIRED", inv.Role, userID, inv.ID, err))
	}
}

func (c *KeyorixCore) revokeSystemRoleGrant(ctx context.Context, inv *models.ProjectInvitation, userID uint) {
	if inv.SystemRole == "" {
		return
	}
	role, err := c.storage.GetRoleByName(ctx, inv.SystemRole)
	if err != nil {
		return
	}
	if err := c.RemoveUserRole(ctx, 0, userID, role.ID, Scope{ProjectID: 0}); err != nil {
		c.auditProjectScoped(ctx, eventInvitationRaceRevokeFailed, userID, 0,
			fmt.Sprintf("failed to revert system role %q granted to user %d by invitation %d: %v — MANUAL CLEANUP REQUIRED", inv.SystemRole, userID, inv.ID, err))
	}
}

func (c *KeyorixCore) revokeAssignmentGrants(ctx context.Context, inv *models.ProjectInvitation, userID uint) {
	if inv.AssignmentsJSON == "" {
		return
	}
	var assignments []ProjectAssignment
	if err := json.Unmarshal([]byte(inv.AssignmentsJSON), &assignments); err != nil {
		return
	}
	for _, a := range assignments {
		if err := c.RemoveProjectMember(ctx, 0, a.ProjectID, userID); err != nil {
			c.auditProjectScoped(ctx, eventInvitationRaceRevokeFailed, userID, a.ProjectID,
				fmt.Sprintf("failed to revert project assignment %q granted to user %d by invitation %d: %v — MANUAL CLEANUP REQUIRED", a.Role, userID, inv.ID, err))
		}
	}
}

// ResendInvitationLink reissues the accept link for a still-pending invitation
// (superseding the prior token) and re-delivers it. Throttled per ADR-028. The
// caller is already verified to be authorized within projectID (below), and the
// supersede itself is scoped to that same project (CORE-INVITATIONS-003) — a resend
// here can only ever kill this project's own prior link for the address.
func (c *KeyorixCore) ResendInvitationLink(ctx context.Context, projectID, invitationID, actorID uint) (*ProvisionSetupResult, error) {
	inv, err := c.storage.GetProjectInvitation(ctx, invitationID)
	if err != nil {
		return nil, fmt.Errorf("invitation not found")
	}
	// The caller is authorized within projectID; an invitation in another project
	// must not be resendable through it (cross-project guard).
	if inv.ProjectID != projectID {
		return nil, fmt.Errorf("invitation not found")
	}
	// Lazy-expire an overdue invite so a resend can't revive a dead one. Best-effort:
	// if the conditional write loses to a concurrent transition (accept/revoke), that
	// transition is authoritative and the state check below still refuses the resend.
	if inv.State == InvitationPending && inv.ExpiresAt != nil && c.now().After(*inv.ExpiresAt) {
		inv.State = InvitationExpired
		_, _ = c.storage.UpdateProjectInvitation(ctx, inv)
	}
	if inv.State != InvitationPending {
		return nil, fmt.Errorf("only a pending invitation can be resent (state is %s)", inv.State)
	}
	return c.provisionSetupLinkThrottled(ctx, IssueSetupTokenRequest{
		Purpose:            SetupPurposeInvitationAccept,
		SubjectEmail:       inv.Email,
		InvitationID:       &inv.ID,
		CreatedBy:          actorID,
		SupersedeProjectID: &inv.ProjectID,
	}, "", fmt.Sprintf("%s on project %d", inv.Role, inv.ProjectID))
}

// ListProjectInvitations returns a project's invitations, marking any pending
// invite past its TTL as expired (lazily, on read).
func (c *KeyorixCore) ListProjectInvitations(ctx context.Context, projectID uint) ([]*models.ProjectInvitation, error) {
	rows, err := c.storage.ListProjectInvitations(ctx, projectID)
	if err != nil {
		return nil, err
	}
	now := c.now()
	for _, inv := range rows {
		if inv.State == InvitationPending && inv.ExpiresAt != nil && now.After(*inv.ExpiresAt) {
			inv.State = InvitationExpired
			// Best-effort: if a concurrent accept/revoke already resolved this
			// invitation, that transition is authoritative — the conditional write
			// no-ops here rather than clobbering it, but the row we return this
			// call is still fine to display with the intended lazy-expiry state.
			_, _ = c.storage.UpdateProjectInvitation(ctx, inv)
		}
	}
	return rows, nil
}

// RevokeInvitation cancels a pending invitation.
func (c *KeyorixCore) RevokeInvitation(ctx context.Context, projectID, invitationID, actorID uint) error {
	inv, err := c.storage.GetProjectInvitation(ctx, invitationID)
	if err != nil {
		return fmt.Errorf("invitation not found")
	}
	if inv.ProjectID != projectID {
		return fmt.Errorf("invitation not found")
	}
	if inv.State != InvitationPending {
		return fmt.Errorf("only a pending invitation can be revoked (state is %s)", inv.State)
	}
	now := c.now()
	inv.State = InvitationRevoked
	inv.RevokedAt = &now
	ok, err := c.storage.UpdateProjectInvitation(ctx, inv)
	if err != nil {
		return fmt.Errorf("failed to revoke invitation: %w", err)
	}
	if !ok {
		// The invitation stopped being pending between the read above and this
		// write — most likely a concurrent accept (completeInvitationAccept) won
		// the race. Refuse rather than silently reporting success while the
		// invitation (and whatever it granted) is left untouched (#412).
		return fmt.Errorf("invitation is no longer pending (it was concurrently accepted or resolved)")
	}
	c.auditProjectScoped(ctx, "invitation.revoked", actorID, inv.ProjectID,
		fmt.Sprintf("revoked invitation %d (%s)", inv.ID, inv.Email))
	return nil
}

// StaleInvitations returns pending invitations older than the cutoff.
func (c *KeyorixCore) StaleInvitations(ctx context.Context, projectID uint, olderThan time.Duration) ([]*models.ProjectInvitation, error) {
	rows, err := c.storage.ListProjectInvitations(ctx, projectID)
	if err != nil {
		return nil, err
	}
	cutoff := c.now().Add(-olderThan)
	var stale []*models.ProjectInvitation
	for _, inv := range rows {
		if inv.State == InvitationPending && inv.CreatedAt.Before(cutoff) {
			stale = append(stale, inv)
		}
	}
	return stale, nil
}

// ── Access requests ──────────────────────────────────────────────────────────

// RequestProjectAccess creates a pending access request for a user to a project.
func (c *KeyorixCore) RequestProjectAccess(ctx context.Context, projectID, userID uint, suggestedRole, reason string) (*models.AccessRequest, error) {
	if projectID == 0 || userID == 0 {
		return nil, fmt.Errorf("project and user IDs are required")
	}
	if suggestedRole != "" {
		if _, err := c.storage.GetRoleByName(ctx, suggestedRole); err != nil {
			return nil, fmt.Errorf("unknown role %q: %w", suggestedRole, err)
		}
	}
	// The target project must exist and be live — GetProject's default soft-delete scope
	// excludes a deleted project, so this also refuses a request against one that has been
	// soft-deleted (#371). Otherwise a request can sit pending against a project an admin
	// believes is gone, waiting to be approved (and go live) whenever it's restored.
	if _, err := c.storage.GetProject(ctx, projectID); err != nil {
		return nil, fmt.Errorf("project %d not found: %w", projectID, err)
	}
	// #G82: refuse a second pending PROJECT-ROLE request for the SAME (user,
	// project) pair — without this, any authenticated user could call this
	// endpoint in a tight loop and flood the project with an unbounded number
	// of pending AccessRequest rows, each firing its own admin notification
	// (notifyAccessRequested below). Scoped to e.SecretID == nil: a
	// SECRET-scoped request (RequestSecretAccess, classification_gate.go)
	// shares the same (UserID, ProjectID) shape but is a semantically
	// different request the user may legitimately have pending at the same
	// time as a project-role request. ListAccessRequests lazily expires stale
	// pending rows on read, so this check is never blocked by a request
	// that's actually expired.
	existing, err := c.storage.ListAccessRequests(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing access requests: %w", err)
	}
	for _, e := range existing {
		if e.UserID == userID && e.State == AccessRequestPending && e.SecretID == nil {
			return nil, fmt.Errorf("you already have a pending access request for this project")
		}
	}
	now := c.now()
	expires := now.Add(accessRequestTTL)
	req := &models.AccessRequest{
		ProjectID:     projectID,
		UserID:        userID,
		SuggestedRole: suggestedRole,
		State:         AccessRequestPending,
		Reason:        reason,
		ExpiresAt:     &expires,
		CreatedAt:     now,
	}
	created, err := c.storage.CreateAccessRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create access request: %w", err)
	}
	c.auditProjectScoped(ctx, "access_request.created", userID, projectID,
		fmt.Sprintf("user %d requested %s access to project %d", userID, suggestedRole, projectID))
	c.notifyAccessRequested(ctx, created)
	return created, nil
}

// ListAccessRequests returns a project's access requests, expiring stale pending
// ones lazily on read.
func (c *KeyorixCore) ListAccessRequests(ctx context.Context, projectID uint) ([]*models.AccessRequest, error) {
	rows, err := c.storage.ListAccessRequests(ctx, projectID)
	if err != nil {
		return nil, err
	}
	now := c.now()
	required := c.requiredApprovals()
	for _, req := range rows {
		if req.State == AccessRequestPending && req.ExpiresAt != nil && now.After(*req.ExpiresAt) {
			req.State = AccessRequestExpired
			// Best-effort lazy expiry: a concurrent approve/reject/withdraw that
			// already resolved this request wins and the conditional write no-ops.
			_, _ = c.storage.UpdateAccessRequest(ctx, req)
		}
		// Annotate the dual-control progress for a pending request.
		if req.State == AccessRequestPending {
			req.RequiredApprovals = required
			if approvals, err := c.storage.ListAccessRequestApprovals(ctx, req.ID); err == nil {
				req.ApprovalsReceived = len(approvals)
			}
		}
	}
	return rows, nil
}

// ApproveAccessRequest approves a pending request, granting grantedRole (falling
// back to the suggested role) at the project scope, permanently. No auto-approval —
// an admin performs this explicitly.
func (c *KeyorixCore) ApproveAccessRequest(ctx context.Context, projectID, requestID, approverID uint, grantedRole string) (*models.AccessRequest, error) {
	return c.ApproveAccessRequestWithExpiry(ctx, projectID, requestID, approverID, grantedRole, 0)
}

// SetDualControlPolicy sets the N-of-M approval threshold for access requests
// (A.5.3). <=1 = single approval (the default).
func (c *KeyorixCore) SetDualControlPolicy(requiredApprovals int) {
	c.dualControlRequiredApprovals = requiredApprovals
}

// requiredApprovals returns the dual-control threshold (minimum 1).
func (c *KeyorixCore) requiredApprovals() int {
	if c.dualControlRequiredApprovals > 1 {
		return c.dualControlRequiredApprovals
	}
	return 1
}

// ApproveAccessRequestWithExpiry records an approver's sign-off on a pending request
// and, once the dual-control threshold of K distinct approvers (none the requester)
// is reached, grants the role — TIME-BOUND when grantTTL > 0 (JIT). Below the
// threshold the request stays pending and the returned request carries the M-of-K
// progress. When K is 1 (the default) the first approval grants immediately.
func (c *KeyorixCore) ApproveAccessRequestWithExpiry(ctx context.Context, projectID, requestID, approverID uint, grantedRole string, grantTTL time.Duration) (*models.AccessRequest, error) {
	// #G04: dualControlApprovalMu holds for the whole read-approvals-decide-
	// grant sequence below — see its doc comment in service.go for why two
	// approvers racing at the exact threshold boundary can otherwise both
	// read a below-threshold count and both finalize the grant.
	c.dualControlApprovalMu.Lock()
	defer c.dualControlApprovalMu.Unlock()
	req, err := c.storage.GetAccessRequest(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("access request not found")
	}
	// The approver is authorized within projectID; a request belonging to another
	// project must not be approvable through it, or the role grant would land in a
	// project the caller has no rights over (cross-project privilege escalation).
	if req.ProjectID != projectID {
		return nil, fmt.Errorf("access request not found")
	}
	if req.State != AccessRequestPending {
		return nil, fmt.Errorf("only a pending request can be approved (state is %s)", req.State)
	}
	// The target project must still be live at approval time (#371) — DeleteProject never
	// touches access_requests, so a request can otherwise sit pending across a project
	// soft-delete and be approved afterward, producing a role grant scoped to a
	// nonexistent project that goes live again — against potentially-stale intent — the
	// moment the project is later restored, with no re-review of whether the original
	// approval still makes sense. GetProject's default soft-delete scope makes this check
	// double as the soft-delete check.
	if _, err := c.storage.GetProject(ctx, req.ProjectID); err != nil {
		return nil, fmt.Errorf("cannot approve: project %d no longer exists", req.ProjectID)
	}
	// Enforce the request's own TTL here, not only on the list path. GetAccessRequest
	// returns the stored record verbatim, so a request whose expiry has passed is still
	// State==pending until something reconciles it — approving it would grant access on a
	// stale request that should have lapsed. Expire it lazily and refuse.
	if req.ExpiresAt != nil && c.now().After(*req.ExpiresAt) {
		req.State = AccessRequestExpired
		// Best-effort: if a concurrent approve/reject/withdraw already resolved this
		// request, the "has expired" refusal below still stands — no role was
		// granted on this path, so there's nothing to unwind either way.
		_, _ = c.storage.UpdateAccessRequest(ctx, req)
		return nil, fmt.Errorf("access request has expired")
	}
	if grantTTL < 0 {
		return nil, fmt.Errorf("grant TTL must not be negative")
	}
	// Maker ≠ checker: a requester cannot approve their own request.
	if approverID == req.UserID {
		return nil, fmt.Errorf("a requester cannot approve their own access request")
	}
	// Determine the role to grant. Under multi-party control (K>1) the role is LOCKED to
	// the request's suggested_role — the value every approver reviews. A per-approver
	// override would let the threshold-crossing approver substitute a higher role than
	// the other K-1 approvers consented to (a dual-control escalation). Single-control
	// (K=1) keeps the approve-with-a-different-role override, where one approver is the
	// whole decision anyway.
	required := c.requiredApprovals()
	role, err := resolveApprovalRole(req, grantedRole, required)
	if err != nil {
		return nil, err
	}
	roleModel, err := c.storage.GetRoleByName(ctx, role)
	if err != nil {
		return nil, fmt.Errorf("unknown role %q: %w", role, err)
	}
	// Privilege ceiling: an approver may not grant an admin role unless they themselves
	// hold admin authority at this project (escalation-by-proxy guard).
	if err := c.requireAuthorityForRole(ctx, approverID, req.ProjectID, role); err != nil {
		return nil, err
	}
	// One sign-off per distinct approver.
	approvals, err := c.storage.ListAccessRequestApprovals(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("failed to read approvals: %w", err)
	}
	if hasAlreadyApproved(approvals, approverID) {
		return nil, fmt.Errorf("you have already approved this request")
	}
	received := len(approvals) + 1
	// Below the threshold: record the approval, stay pending, notify, return progress.
	if received < required {
		return c.recordPartialApproval(ctx, req, requestID, approverID, received, required)
	}
	// Threshold reached — grant the role and finalize.
	return c.finalizeAccessRequestApproval(ctx, req, approverID, roleModel, grantTTL, received, required)
}

// resolveApprovalRole determines the role string to grant for an approval, enforcing
// the dual-control lock when required > 1.
func resolveApprovalRole(req *models.AccessRequest, grantedRole string, required int) (string, error) {
	role := grantedRole
	if role == "" {
		role = req.SuggestedRole
	}
	if required > 1 {
		if req.SuggestedRole == "" {
			return "", fmt.Errorf("a %d-of-N access request must specify the role at request time", required)
		}
		if grantedRole != "" && grantedRole != req.SuggestedRole {
			return "", fmt.Errorf("under %d-of-N approval the granted role is fixed to the requested role %q and cannot be changed by an approver", required, req.SuggestedRole)
		}
		role = req.SuggestedRole
	}
	if role == "" {
		return "", fmt.Errorf("a role to grant is required")
	}
	return role, nil
}

// hasAlreadyApproved reports whether approverID appears in the existing approvals.
func hasAlreadyApproved(approvals []*models.AccessRequestApproval, approverID uint) bool {
	for _, a := range approvals {
		if a.ApproverID == approverID {
			return true
		}
	}
	return false
}

// recordPartialApproval handles the below-threshold path: records the approval, stays
// pending, notifies, and returns progress annotations on the request.
func (c *KeyorixCore) recordPartialApproval(ctx context.Context, req *models.AccessRequest, requestID, approverID uint, received, required int) (*models.AccessRequest, error) {
	if err := c.storage.CreateAccessRequestApproval(ctx, &models.AccessRequestApproval{
		RequestID: requestID, ApproverID: approverID, CreatedAt: c.now(),
	}); err != nil {
		return nil, fmt.Errorf("failed to record approval: %w", err)
	}
	c.auditProjectScoped(ctx, "access_request.approval_recorded", approverID, req.ProjectID,
		fmt.Sprintf("approval %d of %d recorded for access request %d", received, required, req.ID))
	c.notifyApprovalProgress(ctx, req, received, required)
	req.ApprovalsReceived = received
	req.RequiredApprovals = required
	return req, nil
}

// finalizeAccessRequestApproval handles the threshold-reached path: grants the role,
// records the approval, and updates the request state atomically. On a concurrent
// write race (!ok) the grant is reverted and the caller receives an error.
func (c *KeyorixCore) finalizeAccessRequestApproval(ctx context.Context, req *models.AccessRequest, approverID uint, roleModel *models.Role, grantTTL time.Duration, received, required int) (*models.AccessRequest, error) {
	now := c.now()
	scope := storage.Scope{ProjectID: req.ProjectID}
	// Grant the role FIRST so that a grant failure leaves the approval unrecorded
	// (retryable) rather than stuck above-threshold-but-ungranted.
	grantDesc := roleModel.Name
	if grantTTL > 0 {
		expiresAt := now.Add(grantTTL)
		// Routed through the audited wrapper so this grant lands in the RBAC audit
		// trail with a structured RoleID, alongside the generic access_request.approved
		// event below (#298). actorIsMachine=false: unchanged from before #1542 --
		// approverID here isn't threaded from a live actor-kind signal at this call
		// site; a machine-driven approval chain is a sibling finding, not fixed here.
		if err := c.AssignUserRoleWithExpiry(ctx, approverID, req.UserID, roleModel.ID, scope, expiresAt, false); err != nil {
			return nil, fmt.Errorf("failed to grant role: %w", err)
		}
		grantDesc = fmt.Sprintf("%s until %s (TTL %s)", roleModel.Name, expiresAt.UTC().Format(time.RFC3339), grantTTL)
	} else {
		if err := c.AssignUserRole(ctx, approverID, req.UserID, roleModel.ID, scope); err != nil {
			return nil, fmt.Errorf("failed to grant role: %w", err)
		}
	}
	if err := c.storage.CreateAccessRequestApproval(ctx, &models.AccessRequestApproval{
		RequestID: req.ID, ApproverID: approverID, CreatedAt: now,
	}); err != nil {
		return nil, fmt.Errorf("failed to record approval: %w", err)
	}
	req.State = AccessRequestApproved
	req.GrantedRole = roleModel.Name
	req.ResolvedBy = approverID
	req.ResolvedAt = &now
	ok, err := c.storage.UpdateAccessRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to update access request: %w", err)
	}
	if !ok {
		// The request stopped being pending between the read above and this write —
		// most likely a concurrent WithdrawAccessRequest or RejectAccessRequest won
		// the race after the role grant above already landed. The grant must not
		// outlive a request that no longer reads as approved (#277): revoke it and
		// fail closed rather than reporting success with a stale/contradictory state.
		if rerr := c.RemoveUserRole(ctx, approverID, req.UserID, roleModel.ID, scope); rerr != nil {
			c.auditProjectScoped(ctx, "access_request.approval_race_revoke_failed", approverID, req.ProjectID,
				fmt.Sprintf("access request %d was concurrently withdrawn/rejected after granting %s to user %d, and reverting the grant failed: %v — MANUAL CLEANUP REQUIRED", req.ID, roleModel.Name, req.UserID, rerr))
		} else {
			c.auditProjectScoped(ctx, "access_request.approval_race_reverted", approverID, req.ProjectID,
				fmt.Sprintf("access request %d was concurrently withdrawn/rejected; reverted the %s grant just made to user %d", req.ID, roleModel.Name, req.UserID))
		}
		return nil, fmt.Errorf("access request was concurrently withdrawn or resolved; the role grant was reverted")
	}
	c.auditProjectScoped(ctx, "access_request.approved", approverID, req.ProjectID,
		fmt.Sprintf("approved access request %d for user %d as %s (%d approval(s))", req.ID, req.UserID, grantDesc, received))
	c.notifyAccessResolved(ctx, req, true)
	req.ApprovalsReceived = received
	req.RequiredApprovals = required
	return req, nil
}

// notifyApprovalProgress alerts the project's approvers that a request needs more
// sign-offs (best-effort).
func (c *KeyorixCore) notifyApprovalProgress(ctx context.Context, req *models.AccessRequest, received, required int) {
	members, err := c.storage.ListProjectMembers(ctx, req.ProjectID)
	if err != nil {
		return
	}
	pid := req.ProjectID
	label := c.projectLabel(ctx, req.ProjectID)
	link := fmt.Sprintf("/projects/%d", req.ProjectID)
	msg := fmt.Sprintf("Access request %d for %s has %d of %d approvals — another approver is needed.", req.ID, label, received, required)
	for _, mbr := range members {
		if mbr.UserID == req.UserID || !isApproverRole(mbr.RoleName) {
			continue
		}
		c.notify(ctx, mbr.UserID, NotificationAccessRequested, "Access request needs another approval", msg, &pid, link)
	}
}

// RejectAccessRequest rejects a pending request with a reason.
func (c *KeyorixCore) RejectAccessRequest(ctx context.Context, projectID, requestID, approverID uint, reason string) (*models.AccessRequest, error) {
	req, err := c.storage.GetAccessRequest(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("access request not found")
	}
	if req.ProjectID != projectID {
		return nil, fmt.Errorf("access request not found")
	}
	if req.State != AccessRequestPending {
		return nil, fmt.Errorf("only a pending request can be rejected (state is %s)", req.State)
	}
	now := c.now()
	req.State = AccessRequestRejected
	req.Reason = reason
	req.ResolvedBy = approverID
	req.ResolvedAt = &now
	ok, err := c.storage.UpdateAccessRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to update access request: %w", err)
	}
	if !ok {
		// The request stopped being pending between the read above and this write —
		// e.g. a concurrent approval already granted the role and moved it to
		// approved. Refuse rather than silently reporting a rejection that never
		// took effect (#277's TOCTOU pattern, applied here too).
		return nil, fmt.Errorf("access request is no longer pending (it was concurrently approved or resolved)")
	}
	c.auditProjectScoped(ctx, "access_request.rejected", approverID, req.ProjectID,
		fmt.Sprintf("rejected access request %d for user %d", req.ID, req.UserID))
	c.notifyAccessResolved(ctx, req, false)
	return req, nil
}

// WithdrawAccessRequest lets the requester cancel their own pending request.
// #G14: a nonexistent requestID and one that exists but belongs to another
// user both yield the SAME "access request not found" error — a distinct "not
// your access request" message would let a caller enumerate which request IDs
// exist (and are owned by someone else) purely from the response shape.
func (c *KeyorixCore) WithdrawAccessRequest(ctx context.Context, requestID, userID uint) error {
	notFound := fmt.Errorf("access request not found")
	req, err := c.storage.GetAccessRequest(ctx, requestID)
	if err != nil {
		return notFound
	}
	if req.UserID != userID {
		return notFound
	}
	if req.State != AccessRequestPending {
		return fmt.Errorf("only a pending request can be withdrawn (state is %s)", req.State)
	}
	now := c.now()
	req.State = AccessRequestWithdrawn
	req.ResolvedAt = &now
	ok, err := c.storage.UpdateAccessRequest(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to update access request: %w", err)
	}
	if !ok {
		// The request stopped being pending between the read above and this write —
		// e.g. a concurrent approval already granted the role and moved it to
		// approved. Refuse rather than silently reporting a withdrawal that never
		// took effect while a role grant is live behind it (#277).
		return fmt.Errorf("access request is no longer pending (it was concurrently approved or resolved)")
	}
	c.auditProjectScoped(ctx, "access_request.withdrawn", userID, req.ProjectID,
		fmt.Sprintf("withdrew access request %d", req.ID))
	return nil
}

// auditProjectScoped writes a project-scoped audit event with an actor.
func (c *KeyorixCore) auditProjectScoped(ctx context.Context, eventType string, actorID, projectID uint, description string) {
	aid, pid := actorID, projectID
	c.writeAuditEventFull(ctx, eventType, &aid, nil, &pid, "", description)
}
