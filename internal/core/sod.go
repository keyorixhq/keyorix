// sod.go — separation of duties (ISO 27001 A.5.3 / SOX). A SoD policy names two
// permissions that one principal must not hold together (a "toxic combination",
// e.g. "approve access requests" AND "administer secrets"). DetectSoDViolations
// finds the users who effectively hold both sides of any policy. Policies are
// managed by admins (system.write); detection + listing need system.read. The
// violations feed the compliance posture/evidence and the web.
package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SoD audit event types.
const (
	EventSoDPolicyCreated = "sod.policy_created" // #nosec G101 -- audit event type, not a credential
	EventSoDPolicyDeleted = "sod.policy_deleted" // #nosec G101 -- audit event type, not a credential
)

// SoDViolation is one principal (human user or machine identity) that effectively
// holds both permissions a policy forbids together.
type SoDViolation struct {
	PolicyID   uint   `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	// PrincipalType is "user" or "machine". UserID/Username carry the principal's id
	// and label for either kind (the JSON keys stay user_* for backward compatibility).
	PrincipalType string `json:"principal_type"`
	UserID        uint   `json:"user_id"`
	Username      string `json:"username"`
	Email         string `json:"email,omitempty"`
	PermissionA   string `json:"permission_a"`
	PermissionB   string `json:"permission_b"`
	// Detail explains a non-obvious basis for the violation, e.g. that the principal
	// holds both sides only by virtue of an admin permission-bypass role.
	Detail string `json:"detail,omitempty"`
	// Reference is the stable, matchable identifier for this specific violation
	// (policy + principal) — copy it verbatim into a "sod"-category risk
	// exception's Reference field to have that exception suppress THIS violation,
	// and only this one, from the compliance posture (#170).
	Reference string `json:"reference"`
}

// sodViolationReference builds the stable per-(policy, principal) reference a
// governed risk exception matches against to suppress this specific violation.
func sodViolationReference(policyID uint, principalType string, principalID uint) string {
	return fmt.Sprintf("sod:policy:%d:%s:%d", policyID, principalType, principalID)
}

// SoDViolationsReport is the result of a full separation-of-duties scan: every
// violation found, plus a signal for whether the scan is complete. #420: a user
// whose effective permissions could not be read was previously silently skipped
// (`continue`, no logging, no signal) — if that user actually held a toxic
// permission combination, the violation was silently never reported, exactly the
// fail-open shape already fixed elsewhere (CompliancePosture.degrade,
// AccessReviewReport.degrade, SecretAccessorsResult.degrade). Degraded +
// DegradedReasons make the gap detectable instead.
type SoDViolationsReport struct {
	Violations []SoDViolation `json:"violations"`
	// Degraded is true when at least one principal's permissions could not be read,
	// so the scan may be missing a violation for that principal.
	Degraded bool `json:"degraded"`
	// DegradedReasons names each principal whose permissions failed to resolve,
	// with the underlying error.
	DegradedReasons []string `json:"degraded_reasons,omitempty"`
}

// degrade records that a principal's permissions could not be evaluated for SoD
// violations: it flips Degraded and appends a human-readable reason, mirroring
// AccessReviewReport.degrade (access_review.go).
func (r *SoDViolationsReport) degrade(area string, err error) {
	r.Degraded = true
	r.DegradedReasons = append(r.DegradedReasons, fmt.Sprintf("%s: %v", area, err))
}

// CreateSoDPolicy defines a toxic-combination rule. The two permissions must be
// present and distinct. actorID is the creating admin.
func (c *KeyorixCore) CreateSoDPolicy(ctx context.Context, actorID uint, name, description, permA, permB string) (*models.SoDPolicy, error) {
	name = strings.TrimSpace(name)
	permA = strings.TrimSpace(permA)
	permB = strings.TrimSpace(permB)
	if name == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "a policy name is required")
	}
	if permA == "" || permB == "" {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "two permissions are required")
	}
	if permA == permB {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "the two permissions must be different")
	}
	policy, err := c.storage.CreateSoDPolicy(ctx, &models.SoDPolicy{
		Name: name, Description: description, PermissionA: permA, PermissionB: permB,
		CreatedBy: actorID, CreatedAt: c.now(),
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.writeAuditEvent(ctx, EventSoDPolicyCreated, actorPtr(actorID), nil,
		fmt.Sprintf("created SoD policy %d (%q): %s + %s", policy.ID, name, permA, permB))
	return policy, nil
}

// ListSoDPolicies returns all separation-of-duties policies.
func (c *KeyorixCore) ListSoDPolicies(ctx context.Context) ([]*models.SoDPolicy, error) {
	policies, err := c.storage.ListSoDPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return policies, nil
}

// DeleteSoDPolicy retires a policy. actorID is the acting admin.
func (c *KeyorixCore) DeleteSoDPolicy(ctx context.Context, actorID, id uint) error {
	if err := c.storage.DeleteSoDPolicy(ctx, id); err != nil {
		return err
	}
	c.writeAuditEvent(ctx, EventSoDPolicyDeleted, actorPtr(actorID), nil,
		fmt.Sprintf("deleted SoD policy %d", id))
	return nil
}

// DetectSoDViolations evaluates every policy against every active principal's
// effective permissions and returns each that holds both sides of a policy. Empty
// when there are no policies. It covers BOTH human users (paged, no silent cap) and
// machine identities — automation principals hold roles and are authorized too, so
// omitting them would leave the control blind to a whole class of actor. The
// returned report's Degraded/DegradedReasons signal when a principal's permissions
// could not be read, rather than silently reading as "scanned, no violation" (#420).
func (c *KeyorixCore) DetectSoDViolations(ctx context.Context) (*SoDViolationsReport, error) {
	policies, err := c.storage.ListSoDPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	report := &SoDViolationsReport{Violations: []SoDViolation{}}
	if len(policies) == 0 {
		return report, nil
	}

	const pageSize = 500
	for page := 1; ; page++ {
		users, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: page, PageSize: pageSize})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		for _, u := range users {
			if !u.IsActive {
				continue
			}
			uv, err := c.userSoDViolations(ctx, u, policies)
			if err != nil {
				// #420: the user is still skipped (nothing else can be done without
				// the data), but the report must say coverage is incomplete instead
				// of looking like a clean scan that silently missed them.
				report.degrade(fmt.Sprintf("user_permissions:user=%d", u.ID), err)
				continue
			}
			report.Violations = append(report.Violations, uv...)
		}
		if len(users) < pageSize || int64(page*pageSize) >= total {
			break
		}
	}

	report.Violations = append(report.Violations, c.machineSoDViolations(ctx, policies)...)
	return report, nil
}

// userSoDViolations returns the policy violations a single user holds. A user whose
// role set includes an admin permission-bypass role effectively holds EVERY
// permission — Authorize short-circuits on it before ever consulting role_permissions
// — so such a user violates every policy, even though their explicit role_permissions
// rows may name only one side (or neither). Missing that made the SoD control blind to
// exactly the most-privileged principals it exists to police. For a non-admin, the
// held-set unions direct and group-inherited permissions (mirroring Authorize).
//
// #420: an error resolving the user's permissions is returned to the caller rather
// than silently swallowed — the user genuinely can't be scanned without the data, but
// the caller (DetectSoDViolations) must record that the scan is incomplete instead of
// looking clean.
func (c *KeyorixCore) userSoDViolations(ctx context.Context, u *models.User, policies []*models.SoDPolicy) ([]SoDViolation, error) {
	if adminRole := c.adminRoleName(ctx, u.ID); adminRole != "" {
		out := make([]SoDViolation, 0, len(policies))
		detail := fmt.Sprintf("holds all permissions via admin role %q", adminRole)
		for _, pol := range policies {
			out = append(out, SoDViolation{
				PolicyID: pol.ID, PolicyName: pol.Name,
				PrincipalType: "user", UserID: u.ID, Username: u.Username, Email: u.Email,
				PermissionA: pol.PermissionA, PermissionB: pol.PermissionB,
				Detail:    detail,
				Reference: sodViolationReference(pol.ID, "user", u.ID),
			})
		}
		return out, nil
	}

	perms, err := c.storage.GetUserPermissions(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	groupPerms, err := c.storage.GetUserGroupPermissions(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	held := make(map[string]bool, len(perms)+len(groupPerms))
	for _, p := range perms {
		held[p.Name] = true
	}
	for _, p := range groupPerms {
		held[p.Name] = true
	}
	var out []SoDViolation
	for _, pol := range policies {
		if held[pol.PermissionA] && held[pol.PermissionB] {
			out = append(out, SoDViolation{
				PolicyID: pol.ID, PolicyName: pol.Name,
				PrincipalType: "user", UserID: u.ID, Username: u.Username, Email: u.Email,
				PermissionA: pol.PermissionA, PermissionB: pol.PermissionB,
				Reference:   sodViolationReference(pol.ID, "user", u.ID),
			})
		}
	}
	return out, nil
}

// machineSoDViolations scans active machine identities. Machines resolve permissions
// from machine_identity_roles and receive NO admin-role bypass (a leaked machine token
// is bounded to its explicit grants), so the held-set is just the union of its roles'
// permissions. Best-effort: if machine identities can't be listed (e.g. the table
// isn't provisioned in this deployment), machine scanning is skipped rather than
// failing the whole detection.
func (c *KeyorixCore) machineSoDViolations(ctx context.Context, policies []*models.SoDPolicy) []SoDViolation {
	machines, err := c.storage.ListAllMachineIdentities(ctx)
	if err != nil {
		return nil
	}
	var out []SoDViolation
	for _, m := range machines {
		if m.State != "active" {
			continue
		}
		roles, err := c.storage.GetMachineRoles(ctx, m.ID)
		if err != nil || len(roles) == 0 {
			continue
		}
		roleIDs := make([]uint, 0, len(roles))
		for _, r := range roles {
			roleIDs = append(roleIDs, r.ID)
		}
		for _, pol := range policies {
			hasA, err := c.storage.RoleSetHasPermission(ctx, roleIDs, pol.PermissionA)
			if err != nil || !hasA {
				continue
			}
			hasB, err := c.storage.RoleSetHasPermission(ctx, roleIDs, pol.PermissionB)
			if err != nil || !hasB {
				continue
			}
			out = append(out, SoDViolation{
				PolicyID: pol.ID, PolicyName: pol.Name,
				PrincipalType: "machine", UserID: m.ID, Username: m.Name,
				PermissionA: pol.PermissionA, PermissionB: pol.PermissionB,
				Reference:   sodViolationReference(pol.ID, "machine", m.ID),
			})
		}
	}
	return out
}

// adminRoleName returns the name of an admin (permission-bypass) role the user holds
// in ANY scope, or "" if none. The SoD scan is scope-agnostic (it unions a user's
// permissions across scopes), so it checks admin membership the same way.
func (c *KeyorixCore) adminRoleName(ctx context.Context, userID uint) string {
	roles, err := c.storage.GetUserRoles(ctx, userID)
	if err != nil {
		return ""
	}
	for _, r := range roles {
		if isAdminRoleName(r.Name) {
			return r.Name
		}
	}
	return ""
}

// actorPtr returns a *uint for an actor id (nil when 0/unauthenticated).
func actorPtr(id uint) *uint {
	if id == 0 {
		return nil
	}
	a := id
	return &a
}
