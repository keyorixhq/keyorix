// invitations.go — project invitations + access requests (ADR-024).
//
// Two related onboarding flows:
//
//   - Invitations: an admin invites an email to a project with an intended role.
//     State: pending → accepted / revoked / expired. The email/setup-link
//     consumption (accept) is a follow-up; this tracks the pending invite so it
//     can be listed, revoked, and aged out.
//   - Access requests: a user asks for a role in a project. State: pending →
//     approved / rejected / withdrawn / expired. Approval grants the (possibly
//     adjusted) role at the project scope. No auto-approval.
//
// Every transition is audited. TTLs: invitations 14 days, access requests 7 days.
package core

import (
	"context"
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
)

// ── Invitations ────────────────────────────────────────────────────────────

// InviteToProject creates a pending invitation for an email to a project with an
// intended role. It snapshots the current validation mode and sets a 14-day TTL.
func (c *KeyorixCore) InviteToProject(ctx context.Context, projectID uint, email, role string, invitedBy uint) (*models.ProjectInvitation, error) {
	if projectID == 0 || email == "" || role == "" {
		return nil, fmt.Errorf("project ID, email, and role are required")
	}
	if _, err := c.storage.GetRoleByName(ctx, role); err != nil {
		return nil, fmt.Errorf("unknown role %q: %w", role, err)
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
// provisioning fails (e.g. base_url unset), the invitation still exists and is
// returned with a nil result and the error, so the caller can resend rather than
// losing the invite.
func (c *KeyorixCore) InviteToProjectWithLink(ctx context.Context, projectID uint, email, role string, invitedBy uint) (*models.ProjectInvitation, *ProvisionSetupResult, error) {
	inv, err := c.InviteToProject(ctx, projectID, email, role, invitedBy)
	if err != nil {
		return nil, nil, err
	}
	prov, err := c.provisionSetupLink(ctx, IssueSetupTokenRequest{
		Purpose:      SetupPurposeInvitationAccept,
		SubjectEmail: email,
		InvitationID: &inv.ID,
		CreatedBy:    invitedBy,
	}, "", fmt.Sprintf("%s on project %d", role, projectID))
	if err != nil {
		return inv, nil, err
	}
	return inv, prov, nil
}

// ResendInvitationLink reissues the accept link for a still-pending invitation
// (superseding the prior token) and re-delivers it. Throttled per ADR-028.
func (c *KeyorixCore) ResendInvitationLink(ctx context.Context, invitationID, actorID uint) (*ProvisionSetupResult, error) {
	inv, err := c.storage.GetProjectInvitation(ctx, invitationID)
	if err != nil {
		return nil, fmt.Errorf("invitation not found")
	}
	// Lazy-expire an overdue invite so a resend can't revive a dead one.
	if inv.State == InvitationPending && inv.ExpiresAt != nil && c.now().After(*inv.ExpiresAt) {
		inv.State = InvitationExpired
		_ = c.storage.UpdateProjectInvitation(ctx, inv)
	}
	if inv.State != InvitationPending {
		return nil, fmt.Errorf("only a pending invitation can be resent (state is %s)", inv.State)
	}
	if err := c.checkResendThrottle(ctx, SetupPurposeInvitationAccept, inv.Email); err != nil {
		return nil, err
	}
	return c.provisionSetupLink(ctx, IssueSetupTokenRequest{
		Purpose:      SetupPurposeInvitationAccept,
		SubjectEmail: inv.Email,
		InvitationID: &inv.ID,
		CreatedBy:    actorID,
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
			_ = c.storage.UpdateProjectInvitation(ctx, inv)
		}
	}
	return rows, nil
}

// RevokeInvitation cancels a pending invitation.
func (c *KeyorixCore) RevokeInvitation(ctx context.Context, invitationID, actorID uint) error {
	inv, err := c.storage.GetProjectInvitation(ctx, invitationID)
	if err != nil {
		return fmt.Errorf("invitation not found")
	}
	if inv.State != InvitationPending {
		return fmt.Errorf("only a pending invitation can be revoked (state is %s)", inv.State)
	}
	now := c.now()
	inv.State = InvitationRevoked
	inv.RevokedAt = &now
	if err := c.storage.UpdateProjectInvitation(ctx, inv); err != nil {
		return fmt.Errorf("failed to revoke invitation: %w", err)
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
	for _, req := range rows {
		if req.State == AccessRequestPending && req.ExpiresAt != nil && now.After(*req.ExpiresAt) {
			req.State = AccessRequestExpired
			_ = c.storage.UpdateAccessRequest(ctx, req)
		}
	}
	return rows, nil
}

// ApproveAccessRequest approves a pending request, granting grantedRole (falling
// back to the suggested role) at the project scope. No auto-approval — an admin
// performs this explicitly.
func (c *KeyorixCore) ApproveAccessRequest(ctx context.Context, requestID, approverID uint, grantedRole string) (*models.AccessRequest, error) {
	req, err := c.storage.GetAccessRequest(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("access request not found")
	}
	if req.State != AccessRequestPending {
		return nil, fmt.Errorf("only a pending request can be approved (state is %s)", req.State)
	}
	role := grantedRole
	if role == "" {
		role = req.SuggestedRole
	}
	if role == "" {
		return nil, fmt.Errorf("a role to grant is required")
	}
	roleModel, err := c.storage.GetRoleByName(ctx, role)
	if err != nil {
		return nil, fmt.Errorf("unknown role %q: %w", role, err)
	}
	// Grant the role at the project scope.
	if err := c.storage.AssignRole(ctx, req.UserID, roleModel.ID, storage.Scope{ProjectID: req.ProjectID}); err != nil {
		return nil, fmt.Errorf("failed to grant role: %w", err)
	}
	now := c.now()
	req.State = AccessRequestApproved
	req.GrantedRole = role
	req.ResolvedBy = approverID
	req.ResolvedAt = &now
	if err := c.storage.UpdateAccessRequest(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to update access request: %w", err)
	}
	c.auditProjectScoped(ctx, "access_request.approved", approverID, req.ProjectID,
		fmt.Sprintf("approved access request %d for user %d as %s", req.ID, req.UserID, role))
	return req, nil
}

// RejectAccessRequest rejects a pending request with a reason.
func (c *KeyorixCore) RejectAccessRequest(ctx context.Context, requestID, approverID uint, reason string) (*models.AccessRequest, error) {
	req, err := c.storage.GetAccessRequest(ctx, requestID)
	if err != nil {
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
	if err := c.storage.UpdateAccessRequest(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to update access request: %w", err)
	}
	c.auditProjectScoped(ctx, "access_request.rejected", approverID, req.ProjectID,
		fmt.Sprintf("rejected access request %d for user %d", req.ID, req.UserID))
	return req, nil
}

// WithdrawAccessRequest lets the requester cancel their own pending request.
func (c *KeyorixCore) WithdrawAccessRequest(ctx context.Context, requestID, userID uint) error {
	req, err := c.storage.GetAccessRequest(ctx, requestID)
	if err != nil {
		return fmt.Errorf("access request not found")
	}
	if req.UserID != userID {
		return fmt.Errorf("not your access request")
	}
	if req.State != AccessRequestPending {
		return fmt.Errorf("only a pending request can be withdrawn (state is %s)", req.State)
	}
	now := c.now()
	req.State = AccessRequestWithdrawn
	req.ResolvedAt = &now
	if err := c.storage.UpdateAccessRequest(ctx, req); err != nil {
		return fmt.Errorf("failed to update access request: %w", err)
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
