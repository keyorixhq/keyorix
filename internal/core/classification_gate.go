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
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// PermSecretReadRestricted is the permission a user must hold at the secret's
// project scope — in addition to the base "secrets.read" RBAC grant — when
// classification.restricted_requires_permission is enabled. Admin and
// project_admin roles bypass this check via Authorize's admin-role shortcut;
// everyone else needs an explicit grant on their role.
const PermSecretReadRestricted = "secrets.read.restricted"

// defaultMFAStepUpWindow is the fallback step-up window when the config value is 0.
const defaultMFAStepUpWindow = 15 * time.Minute

// SetClassificationRestrictedRequiresApproval mirrors config classification.
// restricted_requires_approval. false (the default, and the zero value) leaves
// "restricted" purely informational — identical to today's behaviour. See
// KeyorixCore.classificationRestrictedRequiresApproval.
func (c *KeyorixCore) SetClassificationRestrictedRequiresApproval(enabled bool) {
	c.classificationRestrictedRequiresApproval = enabled
}

// SetClassificationRestrictedRequiresPermission mirrors config classification.
// restricted_requires_permission. false (the default) leaves the permission gate
// inactive — any user who passes the base secrets.read RBAC check can read a
// "restricted" secret's value. When true, the user must ALSO hold
// PermSecretReadRestricted at the secret's project scope (or be an admin). Can
// be combined with SetClassificationRestrictedRequiresApproval.
func (c *KeyorixCore) SetClassificationRestrictedRequiresPermission(enabled bool) {
	c.classificationRestrictedRequiresPermission = enabled
}

// SetClassificationRestrictedRequiresMFAStepUp mirrors config classification.
// restricted_requires_mfa_stepup and restricted_mfa_stepup_window_minutes.
// When enabled, reading a "restricted" secret requires a recent MFA verification
// (within windowMinutes minutes; 0 = 15 min default). Can be combined with the
// other gate flags.
func (c *KeyorixCore) SetClassificationRestrictedRequiresMFAStepUp(enabled bool, windowMinutes int) {
	c.classificationRestrictedRequiresMFAStepUp = enabled
	if windowMinutes > 0 {
		c.classificationRestrictedMFAStepUpWindow = time.Duration(windowMinutes) * time.Minute
	} else {
		c.classificationRestrictedMFAStepUpWindow = defaultMFAStepUpWindow
	}
}

// mfaStepUpWindow returns the effective step-up window, defaulting when 0.
func (c *KeyorixCore) mfaStepUpWindow() time.Duration {
	if c.classificationRestrictedMFAStepUpWindow > 0 {
		return c.classificationRestrictedMFAStepUpWindow
	}
	return defaultMFAStepUpWindow
}

// checkRestrictedSecretReadApproval is the fail-closed gate every secret VALUE
// read path routes through (see versions.go/secret_render.go). It is a no-op
// unless at least one classification gate setting is active AND the secret's
// classification is exactly ClassificationRestricted — a lower tier is never
// gated regardless of configuration (#128's product decision).
//
// Three independent guards can be active simultaneously; when multiple are on,
// ALL must be satisfied — defense in depth:
//
//  1. restricted_requires_permission: the user must hold PermSecretReadRestricted
//     at the secret's project scope (or be an admin). Checked first — fast RBAC
//     lookup, no per-secret DB query.
//  2. restricted_requires_approval: the user must have an approved, secret-scoped
//     access request. Checked second.
//  3. restricted_requires_mfa_stepup: the user must have completed MFA within the
//     configured step-up window (default 15 min), recorded by VerifyMFALogin.
//
// userID identifies the acting human principal, if any. 0 means the read has no
// identifiable user behind it — a machine/service-account credential, the
// embedded-mode CLI, or any other caller without a user context. Such a read is
// ALWAYS denied when any gate is active: no silent bypass for automation. A
// machine identity that needs a restricted secret goes through the same human
// flow on behalf of a user. Any failure to positively confirm a gate condition —
// including a storage error — denies the read; this never fails open.
func (c *KeyorixCore) checkRestrictedSecretReadApproval(ctx context.Context, secret *models.SecretNode, userID uint) error {
	if !c.classificationRestrictedRequiresApproval && !c.classificationRestrictedRequiresPermission && !c.classificationRestrictedRequiresMFAStepUp {
		return nil
	}
	if secret == nil || secret.Classification != ClassificationRestricted {
		return nil
	}
	if userID == 0 {
		return fmt.Errorf("secret %q is restricted: this read has no identifiable user — automated/machine reads of restricted secrets are always denied when any classification gate is active", secret.Name)
	}

	// Gate 1: narrower RBAC permission (fast path — no per-secret DB query).
	if c.classificationRestrictedRequiresPermission {
		if err := c.checkRestrictedPermissionGate(ctx, secret, userID); err != nil {
			return err
		}
	}
	// Gate 2: approved secret-scoped access request.
	if c.classificationRestrictedRequiresApproval {
		if err := c.checkRestrictedApprovalGate(ctx, secret, userID); err != nil {
			return err
		}
	}
	// Gate 3: recent MFA step-up (completed within the configured window).
	if c.classificationRestrictedRequiresMFAStepUp {
		if err := c.checkRestrictedMFAGate(ctx, secret, userID); err != nil {
			return err
		}
	}

	return nil
}

func (c *KeyorixCore) checkRestrictedPermissionGate(ctx context.Context, secret *models.SecretNode, userID uint) error {
	scope := Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}
	ok, err := c.Authorize(ctx, userID, PermSecretReadRestricted, scope)
	if err != nil {
		return fmt.Errorf("secret %q is restricted: could not verify the %q permission: %w", secret.Name, PermSecretReadRestricted, err)
	}
	if !ok {
		return fmt.Errorf("secret %q is restricted: the %q permission is required at the project scope to read this secret's value", secret.Name, PermSecretReadRestricted)
	}
	return nil
}

func (c *KeyorixCore) checkRestrictedApprovalGate(ctx context.Context, secret *models.SecretNode, userID uint) error {
	ok, err := c.hasApprovedSecretAccessRequest(ctx, secret.ProjectID, secret.ID, userID)
	if err != nil {
		return fmt.Errorf("secret %q is restricted: could not verify an approved access request: %w", secret.Name, err)
	}
	if !ok {
		return fmt.Errorf("secret %q is restricted: an approved access request for this specific secret is required before its value can be read", secret.Name)
	}
	return nil
}

func (c *KeyorixCore) checkRestrictedMFAGate(ctx context.Context, secret *models.SecretNode, userID uint) error {
	grant, err := c.storage.GetActiveMFAStepUpGrant(ctx, userID, c.now())
	if err != nil {
		return fmt.Errorf("secret %q is restricted: could not verify MFA step-up: %w", secret.Name, err)
	}
	if grant == nil {
		return fmt.Errorf("secret %q is restricted: a recent MFA verification (within %s) is required to read this secret's value — re-authenticate with your second factor", secret.Name, c.mfaStepUpWindow())
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
// Future: a grant_expires_at nullable field on AccessRequest would allow
// time-bounded approvals (e.g. "approved for 4 hours"). Until then,
// revoke the AccessRequest row directly to end access.
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
	if req.ExpiresAt != nil {
		// #1653: refuse a now that looks earlier than one this process has
		// already legitimately observed for an access-request approval --
		// see checkAccessRequestApprovalClockNotRegressed's doc comment.
		if err := c.checkAccessRequestApprovalClockNotRegressed(c.now()); err != nil {
			return nil, err
		}
		if c.now().After(*req.ExpiresAt) {
			req.State = AccessRequestExpired
			_, _ = c.storage.UpdateAccessRequest(ctx, req)
			return nil, fmt.Errorf("access request has expired")
		}
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

// accessRequestApprovalClockRegressionTolerance bounds how far now may read
// EARLIER than accessRequestApprovalWatermark before
// checkAccessRequestApprovalClockNotRegressed refuses an approval. Same
// value and rationale as secretExpiryClockRegressionTolerance (versions.go,
// #1632).
const accessRequestApprovalClockRegressionTolerance = 30 * time.Second

// checkAccessRequestApprovalClockNotRegressed refuses to trust now for an
// access-request approval's lazy-expire-and-refuse check if it looks
// EARLIER than a time this process has already legitimately observed for
// this same check (#1653, follow-up to #1632). Shared between
// ApproveSecretAccessRequest (this file) and ApproveAccessRequestWithExpiry
// (invitations.go) -- the same "is this access request's TTL still live"
// question, reached via two entry points, mirroring #1638's
// consumeClockWatermark being shared between ConsumeMFAChallenge and
// ConsumeWebAuthnSession. Both callers' expiry check binds a fresh c.now()
// directly against a DB-loaded ExpiresAt with no seam — a host clock
// stepped backward past a request's real expiry would let an approver
// approve a request that should have already lapsed. Reuses the exact same
// refusal text both callers' own expiry check already returns
// ("access request has expired"), not a distinct message, so a caller
// cannot use it as an oracle confirming clock manipulation had an effect.
func (c *KeyorixCore) checkAccessRequestApprovalClockNotRegressed(now time.Time) error {
	c.accessRequestApprovalWatermarkMu.Lock()
	defer c.accessRequestApprovalWatermarkMu.Unlock()
	if !c.accessRequestApprovalWatermark.IsZero() && now.Before(c.accessRequestApprovalWatermark.Add(-accessRequestApprovalClockRegressionTolerance)) {
		return fmt.Errorf("access request has expired")
	}
	if now.After(c.accessRequestApprovalWatermark) {
		c.accessRequestApprovalWatermark = now
	}
	return nil
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
