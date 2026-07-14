// break_glass.go — self-service emergency access ("break-glass"). When enabled, a
// user can immediately self-grant a configured emergency role, time-bound (it
// auto-expires via the JIT mechanism), with a mandatory written justification. The
// activation is loudly audited (break_glass.activated) and fans out an alert to the
// project's admins, and is recorded as a queryable BreakGlassActivation for
// post-hoc review (NIS2/DORA incident response). Deliberately un-gated by RBAC —
// the whole point is access the user does NOT already have — so the controls are:
// it must be enabled, the activator must be a member of the project (a project-scoped
// role, not merely the global baseline), the emergency role must be contained (it may
// not carry roles.assign, so an auto-expiring grant cannot mint permanent access),
// every use is justified + audited + alerted, and it expires.
package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// minBreakGlassJustificationLen is the minimum length, after trimming
// surrounding whitespace, a break-glass justification must have. This becomes
// a PERMANENT audit-trail record of why a real security incident required
// emergency access, so a bare non-empty check (a single space would pass)
// isn't enough — require something that at least resembles a genuine reason.
const minBreakGlassJustificationLen = 10

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
func (c *KeyorixCore) ActivateBreakGlass(ctx context.Context, projectID, userID uint, justification, ttlOverride string) (*models.BreakGlassActivation, error) { // NOSONAR -- cognitive complexity 28, suppress go:S3776
	if !c.breakGlassPolicy.Enabled {
		return nil, fmt.Errorf("%s", i18n.T("ErrorPermissionDenied", nil))
	}
	if projectID == 0 || userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID and user are required")
	}
	justification = strings.TrimSpace(justification)
	if len(justification) < minBreakGlassJustificationLen {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil),
			fmt.Sprintf("a justification of at least %d characters is required for emergency access", minBreakGlassJustificationLen))
	}
	// Only a user already affiliated with the project may break-glass it. Eligibility
	// must require a role scoped to THIS project (project_id = P), directly or via a
	// group — NOT merely a global/install-wide role. The previous check used
	// GetUserRoleIDsAt, which matches project_id = 0 OR P, so the install baseline
	// (system_viewer, granted globally to every SSO/JIT user) counted as membership and
	// let any authenticated user self-grant the emergency role on ANY project. IsProjectMember
	// excludes global roles, so a user scoped only globally (or to a different project) is refused.
	affiliated, merr := c.storage.IsProjectMember(ctx, userID, projectID)
	if merr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), merr)
	}
	if !affiliated {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "break-glass is available only to members of the project")
	}
	// Refuse a new activation while the user already holds an active, unexpired one on
	// this project — otherwise the time-bound grant becomes indefinitely renewable.
	bgNow := c.now()
	existing, lerr := c.storage.ListBreakGlassActivations(ctx, projectID)
	if lerr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), lerr)
	}
	for _, a := range existing {
		if a.UserID == userID && a.State == BreakGlassActive && a.ExpiresAt != nil && a.ExpiresAt.After(bgNow) {
			return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "you already have an active break-glass grant on this project; revoke it before activating again")
		}
	}
	if c.breakGlassPolicy.EmergencyRole == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "no emergency role is configured")
	}
	role, err := c.storage.GetRoleByName(ctx, c.breakGlassPolicy.EmergencyRole)
	if err != nil {
		return nil, fmt.Errorf("emergency role %q not found: %w", c.breakGlassPolicy.EmergencyRole, err)
	}
	// Refuse an install-wide admin role as the emergency role: break-glass grants at a
	// project scope and must not be a vehicle for install-wide super-user.
	if c.installAdminRoleIDSet(ctx)[role.ID] {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "the configured emergency role grants install-wide administration and cannot be used for break-glass")
	}
	// Refuse an emergency role that can ASSIGN ROLES or issue credentials. The whole
	// security model of break-glass is "it auto-expires", but a time-bound role carrying
	// roles.assign lets the holder mint a PERMANENT grant (or a long-lived machine token)
	// during the window that outlives it — defeating expiry entirely. The emergency role
	// must be powerful-but-contained (e.g. project_developer: read/write/delete secrets,
	// no role administration), NOT project_admin. roles.assign also gates machine-token
	// issuance, so this one check closes both persistence vectors.
	if hasAssign, perr := c.storage.RoleSetHasPermission(ctx, []uint{role.ID}, "roles.assign"); perr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), perr)
	} else if hasAssign {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "the configured emergency role can assign roles or issue credentials and cannot be used for break-glass (it would let an emergency grant create permanent access); configure a contained role such as project_developer")
	}

	defaultTTL := c.breakGlassPolicy.DefaultTTL
	if defaultTTL <= 0 {
		defaultTTL = 4 * time.Hour
	}
	ttl := defaultTTL
	if ttlOverride != "" {
		d, perr := time.ParseDuration(ttlOverride)
		if perr != nil || d <= 0 {
			return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "ttl must be a positive Go duration (e.g. 2h)")
		}
		ttl = d
	}
	// Always bound the grant. When MaxTTL is unconfigured the ceiling falls back to the
	// default TTL — so an override can only ever SHORTEN the grant, never exceed the
	// default. The core enforces "break-glass is time-bound" itself rather than trusting
	// the config layer to have supplied a ceiling; a policy built with MaxTTL=0 (e.g. by
	// a future or non-startup caller) can't yield an unbounded emergency grant.
	ceiling := c.breakGlassPolicy.MaxTTL
	if ceiling <= 0 {
		ceiling = defaultTTL
	}
	if ttl > ceiling {
		ttl = ceiling // cap a requested TTL at the effective ceiling
	}

	now := c.now()
	expiresAt := now.Add(ttl)
	scope := storage.Scope{ProjectID: projectID}

	// Create the activation record FIRST, before granting anything. This is the
	// actual race gate: a partial unique index on (project_id, user_id) WHERE
	// state='active' (ensureBreakGlassActiveIndex) makes the insert itself the source
	// of truth for "at most one active activation", closing the gap in the
	// list-and-scan check above — under a race, two concurrent callers could both pass
	// that check before either inserted. Creating the record before the role grant
	// (rather than after, as before) also means a losing racer here never grants
	// itself the emergency role at all.
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
		if errors.Is(err, storage.ErrBreakGlassAlreadyActive) {
			return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "you already have an active break-glass grant on this project; revoke it before activating again")
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Self-granted: actor == the activating user. Time-bound so it auto-expires. If
	// this fails, the activation record already claimed the race slot above but no
	// access was actually granted — reconcile it to revoked rather than leaving a
	// phantom "active" record with no corresponding role, and free the slot so the
	// user can retry.
	//
	// Deliberately calls assignUserRoleWithExpirySkipSoD, not AssignUserRoleWithExpiry:
	// break-glass is un-gated by design (the whole point is access the user does NOT
	// already have), so it must not be refused by the #419 separation-of-duties
	// preventive gate during a genuine incident — see that function's doc comment
	// (jit_access.go).
	if err := c.assignUserRoleWithExpirySkipSoD(ctx, userID, userID, role.ID, scope, expiresAt); err != nil {
		activation.State = BreakGlassRevoked
		activation.RevokedAt = &now
		_ = c.storage.UpdateBreakGlassActivation(ctx, activation)
		return nil, fmt.Errorf("failed to grant emergency role: %w", err)
	}

	c.auditProjectScoped(ctx, EventBreakGlassActivated, userID, projectID,
		fmt.Sprintf("break-glass: user %d self-granted %q until %s — %s",
			userID, role.Name, expiresAt.UTC().Format(time.RFC3339), justification))
	// The grant is already committed and audited above, so a notification failure here
	// is a DETECTION-LATENCY gap, not a control failure — don't fail the activation on
	// it. But silently swallowing it would defeat break-glass's "loud by design" intent
	// if the notification pipeline itself is down, so surface it loudly (#166): a
	// SECURITY-prefixed log line, matching the convention emitAudit already uses for a
	// failed audit write, so an operational alerting pipeline watching logs still pages.
	if nerr := c.notifyBreakGlassAdmins(ctx, userID, projectID, role.Name, expiresAt); nerr != nil {
		log.Printf("SECURITY: break-glass activation %d (project %d, user %d): admin notification failed: %v",
			activation.ID, projectID, userID, nerr)
	}
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
	// Remove the grant early. A benign "the row is already gone" case (it already
	// auto-expired, or a racing revoke already removed it — see the conditional
	// state transition below) is not an error: proceed to reconcile the record. A
	// genuine storage failure, however, must abort the revoke here — proceeding to
	// mark the record "revoked" while the removal itself failed would leave the
	// emergency role grant LIVE in user_roles (the table RBAC actually reads) but
	// reported as revoked everywhere else (API response, audit trail).
	scope := storage.Scope{ProjectID: projectID}
	if err := c.RemoveUserRole(ctx, actorID, activation.UserID, activation.RoleID, scope); err != nil && !errors.Is(err, storage.ErrRoleNotAssigned) {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	// Conditional UPDATE (WHERE state = active), not a read-modify-write: the initial
	// state check above is only a fast-path convenience, not the enforcement — two
	// concurrent revokes of the same activation can both pass it. Only the first
	// concurrent caller's conditional update actually transitions state; the second
	// gets ErrBreakGlassNotActive instead of silently overwriting RevokedBy/RevokedAt.
	now := c.now()
	if err := c.storage.RevokeBreakGlassActivation(ctx, activation.ID, actorID, now); err != nil {
		if errors.Is(err, storage.ErrBreakGlassNotActive) {
			return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "activation is not active")
		}
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.auditProjectScoped(ctx, EventBreakGlassRevoked, actorID, projectID,
		fmt.Sprintf("break-glass: revoked activation %d (user %d, role %q) early", activation.ID, activation.UserID, activation.RoleName))
	return nil
}

// notifyBreakGlassAdmins alerts the project's approver-role members that emergency
// access was activated. Individual notify() delivery is still best-effort (an
// email/webhook sink hiccup for one admin shouldn't abort the fan-out to the
// others), but a failure to even LIST the project's members is a distinct, louder
// failure mode — it means NO admin was considered for the alert at all — so that
// case is returned as an error (#166) rather than swallowed silently.
func (c *KeyorixCore) notifyBreakGlassAdmins(ctx context.Context, actorID, projectID uint, roleName string, expiresAt time.Time) error {
	members, err := c.storage.ListProjectMembers(ctx, projectID)
	if err != nil {
		return fmt.Errorf("list project %d members: %w", projectID, err)
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
	return nil
}
