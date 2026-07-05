// classification_gate.go — read-time enforcement for the highest data-
// classification tier ("restricted", see classification.go's package doc).
//
// Off by default (config classification.restricted_requires_approval, mirrored
// in-process as KeyorixCore.classificationRestrictedRequiresApproval): with the
// setting off, this file changes nothing — every existing deployment, and every
// pre-existing test, is completely unaffected. See classification.go for why
// this had to stay opt-in rather than becoming an automatic control the moment a
// secret is labelled "restricted".
//
// When the setting is on, a direct read of a "restricted" secret's VALUE (not
// its metadata — GetSecret/ListSecrets never consult this gate, only the
// GetSecretValue*/GetSecretValueByVersion* family does, via
// checkRestrictedSecretReadApproval) requires an approved, secret-scoped access
// request. This reuses the AccessRequest model/table and its whole state
// machine, storage, audit, and notification conventions from invitations.go
// (ADR-024) — the smallest safe extension found: a nullable AccessRequest.
// SecretID narrows a request from "role at a project" to "read this one secret".
//
// It deliberately does NOT reuse ApproveAccessRequestWithExpiry to resolve a
// secret-scoped request: that function's entire body is about granting an RBAC
// role (dual-control math keyed to a role name, the escalation-ceiling check
// scoped to roles, "a role to grant is required" as a hard precondition) and a
// secret-scoped approval grants no role at all — bending it to accept an empty
// role would be forcing a project/role-shaped function into a shape it wasn't
// designed for. RequestSecretAccess/ApproveSecretAccessRequest are new, narrow
// functions built for exactly this; RejectAccessRequest and
// WithdrawAccessRequest, which do nothing role-specific, are reused unchanged —
// they already work for a SecretID-scoped row exactly as they do for a
// project/role one.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SetClassificationRestrictedRequiresApproval mirrors config classification.
// restricted_requires_approval. false (the default, and the zero value) leaves
// "restricted" purely informational — identical to today's behaviour. See
// KeyorixCore.classificationRestrictedRequiresApproval.
func (c *KeyorixCore) SetClassificationRestrictedRequiresApproval(enabled bool) {
	c.classificationRestrictedRequiresApproval = enabled
}

// checkRestrictedSecretReadApproval is the fail-closed gate every secret VALUE
// read path routes through (see versions.go/secret_render.go). It is a no-op
// (nil, nil) unless BOTH the setting is on AND the secret's own classification is
// exactly ClassificationRestricted — a lower tier is never gated, regardless of
// the setting (#128's product decision only concerns the highest tier).
//
// userID identifies the acting human principal, if any. 0 means the read has no
// identifiable user behind it — a machine/service-account credential (the HTTP
// handlers' isMachine branch calls the base GetSecretValue with no userID at
// all), the embedded-mode CLI (which has no user/session concept either), or any
// other caller that cannot present one. Such a read is ALWAYS denied when the
// gate is active: there is no "wait for approval" for automation, and — just as
// importantly — no quiet exemption for it either. A machine identity that
// legitimately needs a restricted secret goes through the exact same
// RequestSecretAccess/ApproveSecretAccessRequest flow as a human would, on
// behalf of a user who then reads it, rather than being carved out as a bypass.
//
// Any failure to positively confirm approval — including a storage error while
// checking — denies the read; this never fails open.
func (c *KeyorixCore) checkRestrictedSecretReadApproval(ctx context.Context, secret *models.SecretNode, userID uint) error {
	if !c.classificationRestrictedRequiresApproval {
		return nil
	}
	if secret == nil || secret.Classification != ClassificationRestricted {
		return nil
	}
	if userID == 0 {
		return fmt.Errorf("secret %q is restricted: reading its value requires an approved access request, and this read has no identifiable user to check one against", secret.Name)
	}
	ok, err := c.hasApprovedSecretAccessRequest(ctx, secret.ProjectID, secret.ID, userID)
	if err != nil {
		return fmt.Errorf("secret %q is restricted: could not verify an approved access request: %w", secret.Name, err)
	}
	if !ok {
		return fmt.Errorf("secret %q is restricted: an approved access request for this specific secret is required before its value can be read", secret.Name)
	}
	return nil
}

// hasApprovedSecretAccessRequest reports whether userID holds a still-approved
// (not later withdrawn/rejected — those are terminal states a request can't
// leave) secret-scoped AccessRequest for secretID. Approval is permanent once
// granted (no separate re-expiry), the same default as a project/role request
// approved with no grant TTL — mirrored here for consistency rather than
// inventing a second expiry model.
//
// Listing by project and filtering in memory reuses the existing
// ListAccessRequests storage method as-is (no storage interface change): access
// requests per project are not high-cardinality, and this mirrors the same
// list-then-filter pattern ApproveAccessRequestWithExpiry itself uses for
// ListAccessRequestApprovals.
func (c *KeyorixCore) hasApprovedSecretAccessRequest(ctx context.Context, projectID, secretID, userID uint) (bool, error) {
	rows, err := c.storage.ListAccessRequests(ctx, projectID)
	if err != nil {
		return false, err
	}
	for _, req := range rows {
		if req.SecretID != nil && *req.SecretID == secretID && req.UserID == userID && req.State == AccessRequestApproved {
			return true, nil
		}
	}
	return false, nil
}

// RequestSecretAccess creates a pending, secret-scoped access request: approval
// to read ONE specific secret's value, distinct from RequestProjectAccess's
// broader project/role grant. Reuses the AccessRequest model/table and the
// standard accessRequestTTL (ADR-024); the project is inferred from the secret.
func (c *KeyorixCore) RequestSecretAccess(ctx context.Context, secretID, userID uint, reason string) (*models.AccessRequest, error) {
	if secretID == 0 || userID == 0 {
		return nil, fmt.Errorf("secret ID and user ID are required")
	}
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("secret %d not found: %w", secretID, err)
	}
	now := c.now()
	expires := now.Add(accessRequestTTL)
	sid := secretID
	req := &models.AccessRequest{
		ProjectID: secret.ProjectID,
		UserID:    userID,
		SecretID:  &sid,
		State:     AccessRequestPending,
		Reason:    reason,
		ExpiresAt: &expires,
		CreatedAt: now,
	}
	created, err := c.storage.CreateAccessRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret access request: %w", err)
	}
	c.auditProjectScoped(ctx, "access_request.secret_created", userID, secret.ProjectID,
		fmt.Sprintf("user %d requested access to read secret %d (%s)", userID, secretID, secret.Name))
	c.notifySecretAccessRequested(ctx, created, secret)
	return created, nil
}

// ApproveSecretAccessRequest approves a pending secret-scoped access request,
// letting the classification gate above find it on the requester's next read.
// Unlike ApproveAccessRequestWithExpiry, no role is granted — approval only
// flips State to approved. Refuses (does not silently no-op) a request whose
// SecretID is nil: that is a project/role request and belongs to
// ApproveAccessRequestWithExpiry instead.
func (c *KeyorixCore) ApproveSecretAccessRequest(ctx context.Context, requestID, approverID uint) (*models.AccessRequest, error) {
	req, err := c.storage.GetAccessRequest(ctx, requestID)
	if err != nil {
		return nil, fmt.Errorf("access request not found")
	}
	if req.SecretID == nil {
		return nil, fmt.Errorf("access request %d is a project/role request, not a secret-scoped one — use ApproveAccessRequestWithExpiry", requestID)
	}
	if req.State != AccessRequestPending {
		return nil, fmt.Errorf("only a pending request can be approved (state is %s)", req.State)
	}
	secret, err := c.storage.GetSecret(ctx, *req.SecretID)
	if err != nil {
		return nil, fmt.Errorf("cannot approve: secret %d no longer exists", *req.SecretID)
	}
	// Mirrors ApproveAccessRequestWithExpiry's own lazy-expire-and-refuse (#277):
	// GetAccessRequest returns the row verbatim, so a request whose TTL already
	// lapsed is still State==pending until something reconciles it.
	if req.ExpiresAt != nil && c.now().After(*req.ExpiresAt) {
		req.State = AccessRequestExpired
		_, _ = c.storage.UpdateAccessRequest(ctx, req)
		return nil, fmt.Errorf("access request has expired")
	}
	// Maker ≠ checker, same as the project/role flow.
	if approverID == req.UserID {
		return nil, fmt.Errorf("a requester cannot approve their own access request")
	}
	// Approving read access to a "restricted" secret is at least as sensitive as
	// granting a non-admin project role, so it carries the same admin-authority
	// ceiling requireAuthorityForRole applies to an admin-role grant — there is no
	// weaker "roles.assign"-shaped permission that fits (this grants no role at
	// all), so the bar is set at the ceiling rather than invented lower.
	if err := c.requireAdminAuthorityAt(ctx, approverID, req.ProjectID); err != nil {
		return nil, fmt.Errorf("only an administrator can approve access to a restricted secret: %w", err)
	}
	now := c.now()
	req.State = AccessRequestApproved
	req.ResolvedBy = approverID
	req.ResolvedAt = &now
	ok, err := c.storage.UpdateAccessRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to update access request: %w", err)
	}
	if !ok {
		// The request stopped being pending between the read above and this write —
		// e.g. a concurrent withdraw won the race. Nothing was granted on this path
		// (no role, no side effect besides the row itself), so unlike the project/
		// role flow there is nothing to revert — just refuse (#277's pattern, the
		// no-grant-to-unwind case).
		return nil, fmt.Errorf("access request is no longer pending (it was concurrently withdrawn or resolved)")
	}
	c.auditProjectScoped(ctx, "access_request.secret_approved", approverID, req.ProjectID,
		fmt.Sprintf("approved access request %d for user %d to read secret %d (%s)", req.ID, req.UserID, *req.SecretID, secret.Name))
	c.notifySecretAccessResolved(ctx, req, secret, true)
	return req, nil
}

// notifySecretAccessRequested alerts the project's approvers of a new
// secret-scoped access request, mirroring notifyAccessRequested but naming the
// secret rather than a suggested role (there isn't one on this path).
func (c *KeyorixCore) notifySecretAccessRequested(ctx context.Context, req *models.AccessRequest, secret *models.SecretNode) {
	members, err := c.storage.ListProjectMembers(ctx, req.ProjectID)
	if err != nil {
		return
	}
	pid := req.ProjectID
	link := fmt.Sprintf("/projects/%d", req.ProjectID)
	for _, mbr := range members {
		if mbr.UserID == req.UserID || !isApproverRole(mbr.RoleName) {
			continue
		}
		c.notify(ctx, mbr.UserID, NotificationAccessRequested,
			"New secret access request",
			fmt.Sprintf("User %d requested access to read secret %q.", req.UserID, secret.Name),
			&pid, link)
	}
}

// notifySecretAccessResolved tells the requester their secret-scoped request was
// approved/rejected, mirroring notifyAccessResolved.
func (c *KeyorixCore) notifySecretAccessResolved(ctx context.Context, req *models.AccessRequest, secret *models.SecretNode, approved bool) {
	pid := req.ProjectID
	link := fmt.Sprintf("/projects/%d", req.ProjectID)
	if approved {
		c.notify(ctx, req.UserID, NotificationAccessApproved,
			"Secret access request approved",
			fmt.Sprintf("Your request to read secret %q was approved.", secret.Name),
			&pid, link)
		return
	}
	c.notify(ctx, req.UserID, NotificationAccessRejected,
		"Secret access request rejected",
		fmt.Sprintf("Your request to read secret %q was rejected.", secret.Name),
		&pid, link)
}
