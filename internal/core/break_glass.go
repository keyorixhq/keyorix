// break_glass.go — self-service emergency access ("break-glass"). When enabled, a
// user can immediately self-grant a configured emergency role, time-bound (it
// auto-expires via the JIT mechanism), with a mandatory written justification. The
// activation is loudly audited (break_glass.activated) and fans out an alert to the
// project's admins, and is recorded as a queryable BreakGlassActivation for
// post-hoc review (NIS2/DORA incident response). Deliberately un-gated by RBAC —
// the whole point is access the user does NOT already have — so the controls are:
// it must be enabled, every use is justified + audited + alerted, and it expires.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Break-glass states and audit events.
const (
	BreakGlassActive  = "active"
	BreakGlassExpired = "expired"
	BreakGlassRevoked = "revoked"

	EventBreakGlassActivated = "break_glass.activated" // #nosec G101 -- audit event type, not a credential
	EventBreakGlassRevoked   = "break_glass.revoked"   // #nosec G101 -- audit event type, not a credential
)

// BreakGlassPolicy is the deployment configuration for emergency access, wired from
// config at startup via SetBreakGlassPolicy.
type BreakGlassPolicy struct {
	Enabled       bool
	EmergencyRole string
	DefaultTTL    time.Duration
	MaxTTL        time.Duration
}

// SetBreakGlassPolicy configures self-service emergency access (default: disabled).
func (c *KeyorixCore) SetBreakGlassPolicy(p BreakGlassPolicy) {
	c.breakGlassPolicy = p
}

// ActivateBreakGlass immediately grants the requesting user the configured emergency
// role at the project scope, time-bound (default or a capped requested TTL), records
// the justified activation, audits it loudly, and alerts the project's admins.
// userID is the activating (self) user; ttlOverride is an optional Go duration.
func (c *KeyorixCore) ActivateBreakGlass(ctx context.Context, projectID, userID uint, justification, ttlOverride string) (*models.BreakGlassActivation, error) {
	if !c.breakGlassPolicy.Enabled {
		return nil, fmt.Errorf("%s", i18n.T("ErrorPermissionDenied", nil))
	}
	if projectID == 0 || userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID and user are required")
	}
	if justification == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "a justification is required for emergency access")
	}
	if c.breakGlassPolicy.EmergencyRole == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "no emergency role is configured")
	}
	role, err := c.storage.GetRoleByName(ctx, c.breakGlassPolicy.EmergencyRole)
	if err != nil {
		return nil, fmt.Errorf("emergency role %q not found: %w", c.breakGlassPolicy.EmergencyRole, err)
	}

	ttl := c.breakGlassPolicy.DefaultTTL
	if ttl <= 0 {
		ttl = 4 * time.Hour
	}
	if ttlOverride != "" {
		d, perr := time.ParseDuration(ttlOverride)
		if perr != nil || d <= 0 {
			return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "ttl must be a positive Go duration (e.g. 2h)")
		}
		ttl = d
	}
	if max := c.breakGlassPolicy.MaxTTL; max > 0 && ttl > max {
		ttl = max // cap a requested TTL at the configured ceiling
	}

	now := c.now()
	expiresAt := now.Add(ttl)
	scope := storage.Scope{ProjectID: projectID}
	// Self-granted: actor == the activating user. Time-bound so it auto-expires.
	if err := c.AssignUserRoleWithExpiry(ctx, userID, userID, role.ID, scope, expiresAt); err != nil {
		return nil, fmt.Errorf("failed to grant emergency role: %w", err)
	}

	activation, err := c.storage.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID:     projectID,
		UserID:        userID,
		RoleID:        role.ID,
		RoleName:      role.Name,
		Justification: justification,
		State:         BreakGlassActive,
		ExpiresAt:     &expiresAt,
		CreatedAt:     now,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	c.auditProjectScoped(ctx, EventBreakGlassActivated, userID, projectID,
		fmt.Sprintf("break-glass: user %d self-granted %q until %s — %s",
			userID, role.Name, expiresAt.UTC().Format(time.RFC3339), justification))
	c.notifyBreakGlassAdmins(ctx, userID, projectID, role.Name, expiresAt)
	return activation, nil
}

// ListBreakGlassActivations returns the project's activations, newest first. An
// active record whose expiry has passed is reported as expired (the grant is gone
// by then, swept or filtered out — the record's stored state is reconciled lazily).
func (c *KeyorixCore) ListBreakGlassActivations(ctx context.Context, projectID uint) ([]*models.BreakGlassActivation, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}
	rows, err := c.storage.ListBreakGlassActivations(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	now := c.now()
	for _, a := range rows {
		if a.State == BreakGlassActive && a.ExpiresAt != nil && a.ExpiresAt.Before(now) {
			a.State = BreakGlassExpired
		}
	}
	return rows, nil
}

// RevokeBreakGlass ends an active emergency grant early: removes the role assignment
// (best-effort — it may already have auto-expired) and marks the record revoked.
// actorID is the admin performing the revoke.
func (c *KeyorixCore) RevokeBreakGlass(ctx context.Context, actorID, projectID, activationID uint) error {
	if projectID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}
	activation, err := c.storage.GetBreakGlassActivation(ctx, activationID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	if activation.ProjectID != projectID {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	if activation.State != BreakGlassActive {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "activation is not active")
	}
	// Remove the grant early. If it already auto-expired the row is gone — ignore
	// that error and still reconcile the record.
	scope := storage.Scope{ProjectID: projectID}
	_ = c.RemoveUserRole(ctx, actorID, activation.UserID, activation.RoleID, scope)

	now := c.now()
	activation.State = BreakGlassRevoked
	activation.RevokedBy = actorID
	activation.RevokedAt = &now
	if err := c.storage.UpdateBreakGlassActivation(ctx, activation); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.auditProjectScoped(ctx, EventBreakGlassRevoked, actorID, projectID,
		fmt.Sprintf("break-glass: revoked activation %d (user %d, role %q) early", activation.ID, activation.UserID, activation.RoleName))
	return nil
}

// notifyBreakGlassAdmins alerts the project's approver-role members that emergency
// access was activated (best-effort).
func (c *KeyorixCore) notifyBreakGlassAdmins(ctx context.Context, actorID, projectID uint, roleName string, expiresAt time.Time) {
	members, err := c.storage.ListProjectMembers(ctx, projectID)
	if err != nil {
		return
	}
	pid := projectID
	title := "Break-glass emergency access activated"
	msg := fmt.Sprintf("User %d self-granted emergency role %q until %s. Review the audit trail.",
		actorID, roleName, expiresAt.UTC().Format(time.RFC3339))
	link := fmt.Sprintf("/projects/%d/access-review", projectID)
	for _, m := range members {
		if !isApproverRole(m.RoleName) {
			continue
		}
		c.notify(ctx, m.UserID, EventBreakGlassActivated, title, msg, &pid, link)
	}
}
