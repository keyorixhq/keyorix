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
	EventSoDPolicyCreated            = "sod.policy_created"             // #nosec G101 -- audit event type, not a credential
	EventSoDPolicyDeleted            = "sod.policy_deleted"             // #nosec G101 -- audit event type, not a credential
	EventSoDPreExistingViolations    = "sod.pre_existing_violations"    // #nosec G101 -- audit event type, not a credential
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

	// SOD-001: scan for principals that already hold both sides of the new policy.
	// Violations are recorded via audit events so operators are immediately alerted;
	// they do not prevent creation (the policy is already persisted above).
	if report, scanErr := c.scanPolicyViolations(ctx, policy); scanErr == nil && len(report.Violations) > 0 {
		c.writeAuditEvent(ctx, EventSoDPreExistingViolations, actorPtr(actorID), nil,
			fmt.Sprintf("new SoD policy %d (%q) has %d pre-existing violation(s); run DetectSoDViolations to enumerate them", policy.ID, name, len(report.Violations)))
	}

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
		c.appendUserSoDViolations(ctx, report, users, policies)
		if len(users) < pageSize || int64(page*pageSize) >= total {
			break
		}
	}

	c.machineSoDViolations(ctx, report, policies)
	return report, nil
}

// scanPolicyViolations runs DetectSoDViolations scoped to a single policy.
// Used by CreateSoDPolicy to detect pre-existing violators without re-scanning
// every existing policy on every creation.
func (c *KeyorixCore) scanPolicyViolations(ctx context.Context, policy *models.SoDPolicy) (*SoDViolationsReport, error) {
	policies := []*models.SoDPolicy{policy}
	report := &SoDViolationsReport{Violations: []SoDViolation{}}
	const pageSize = 500
	for page := 1; ; page++ {
		users, total, err := c.storage.ListUsers(ctx, &storage.UserFilter{Page: page, PageSize: pageSize})
		if err != nil {
			return nil, err
		}
		c.appendUserSoDViolations(ctx, report, users, policies)
		if len(users) < pageSize || int64(page*pageSize) >= total {
			break
		}
	}
	c.machineSoDViolations(ctx, report, policies)
	return report, nil
}

// userSoDViolations returns the policy violations a single user holds. A user whose
// role set includes an admin permission-bypass role effectively holds EVERY
// permission — Authorize short-circuits on it before ever consulting role_permissions
// — so such a user violates every policy, even though their explicit role_permissions
// rows may name only one side (or neither). Missing that made the SoD control blind to
// exactly the most-privileged principals it exists to police. For a non-admin, the
// appendUserSoDViolations iterates a page of users and adds any violations to
// the report. Inactive users are skipped. Permission-resolution errors degrade
// the report rather than abort the scan (#420).
func (c *KeyorixCore) appendUserSoDViolations(ctx context.Context, report *SoDViolationsReport, users []*models.User, policies []*models.SoDPolicy) {
	for _, u := range users {
		if !u.IsActive {
			continue
		}
		uv, err := c.userSoDViolations(ctx, u, policies)
		if err != nil {
			report.degrade(fmt.Sprintf("user_permissions:user=%d", u.ID), err)
			continue
		}
		report.Violations = append(report.Violations, uv...)
	}
}

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

	held, err := c.userHeldPermissionSet(ctx, u.ID)
	if err != nil {
		return nil, err
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

// userHeldPermissionSet returns the set of permission names userID holds via
// DIRECT role assignments and GROUP-inherited roles — NOT the admin-bypass
// (callers that need bypass-awareness check adminRoleName separately, exactly as
// userSoDViolations already does above). Shared by the periodic scan
// (userSoDViolations) and the grant-time preventive check (requireNoSoDViolation
// and friends, #419) so both compute "what does this principal effectively hold"
// identically — one policy-matching rule, not two.
func (c *KeyorixCore) userHeldPermissionSet(ctx context.Context, userID uint) (map[string]bool, error) {
	perms, err := c.storage.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}
	groupPerms, err := c.storage.GetUserGroupPermissions(ctx, userID)
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
	return held, nil
}

// machineSoDViolations scans active machine identities, appending any violations
// found directly onto report.Violations. Machines resolve permissions from
// machine_identity_roles and receive NO admin-role bypass (a leaked machine token
// is bounded to its explicit grants), so the held-set is just the union of its
// roles' permissions.
//
// #492: sibling of userSoDViolations/#420 — every sub-check error here was
// previously silently discarded (ListAllMachineIdentities returning nil,
// GetMachineRoles/RoleSetHasPermission folded into a bare `continue`), so a
// machine identity that actually held a toxic combination could be dropped from
// the scan while the report still looked clean. Each failure now flips
// report.Degraded via report.degrade, named for the machine (and policy, for the
// permission checks) that couldn't be evaluated, instead of looking clean.
func (c *KeyorixCore) machineSoDViolations(ctx context.Context, report *SoDViolationsReport, policies []*models.SoDPolicy) { // NOSONAR -- cognitive complexity 24, suppress go:S3776
	machines, err := c.storage.ListAllMachineIdentities(ctx)
	if err != nil {
		report.degrade("machine_identities", err)
		return
	}
	for _, m := range machines {
		if m.State != "active" {
			continue
		}
		roles, err := c.storage.GetMachineRoles(ctx, m.ID)
		if err != nil {
			report.degrade(fmt.Sprintf("machine_roles:machine=%d", m.ID), err)
			continue
		}
		if len(roles) == 0 {
			continue
		}
		roleIDs := make([]uint, 0, len(roles))
		for _, r := range roles {
			roleIDs = append(roleIDs, r.ID)
		}
		for _, pol := range policies {
			hasA, err := c.storage.RoleSetHasPermission(ctx, roleIDs, pol.PermissionA)
			if err != nil {
				report.degrade(fmt.Sprintf("machine_permission:machine=%d:policy=%d", m.ID, pol.ID), err)
				continue
			}
			if !hasA {
				continue
			}
			hasB, err := c.storage.RoleSetHasPermission(ctx, roleIDs, pol.PermissionB)
			if err != nil {
				report.degrade(fmt.Sprintf("machine_permission:machine=%d:policy=%d", m.ID, pol.ID), err)
				continue
			}
			if !hasB {
				continue
			}
			report.Violations = append(report.Violations, SoDViolation{
				PolicyID: pol.ID, PolicyName: pol.Name,
				PrincipalType: "machine", UserID: m.ID, Username: m.Name,
				PermissionA: pol.PermissionA, PermissionB: pol.PermissionB,
				Reference:   sodViolationReference(pol.ID, "machine", m.ID),
			})
		}
	}
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

// ── Preventive gate (#419) ───────────────────────────────────────────────────
//
// DetectSoDViolations above is a purely periodic/on-demand DETECTIVE control — it
// only catches a toxic-permission overlap when someone runs it (a scheduled
// digest or an on-demand call). Combined with this codebase's JIT/time-bound
// role grants (UserRole.ExpiresAt and friends), a toxic overlap that both STARTS
// and FULLY EXPIRES between two scans is genuinely exercisable through the live
// Authorize() path — real access is granted and can be used during that window —
// but never appears in any SoD violation report: a timing-based evasion of the
// control, concretely constructible by arranging two overlapping short-lived
// grants.
//
// The functions below are the PREVENTIVE counterpart. Called from every direct
// role-grant choke point, before a new grant lands, they reuse the exact same
// policy-matching rule the periodic scan uses (sodPolicyNewlyCompletedBy) to ask
// a narrower, single-principal (or single-grant-set) question — "would THIS
// grant, together with what the principal ALREADY holds, complete a policy that
// isn't already complete?" — and BLOCK the grant if so (fail closed, matching
// this codebase's established posture for every other grant-time ceiling check:
// requireGranterHoldsRolePermissions, requireAuthorityForRole).
//
// Deliberately out of scope below: a principal who ALREADY holds (or is being
// granted) an admin permission-bypass role (isAdminRoleName). An admin holds
// every permission and so trivially "violates" every SoD policy the instant one
// is defined — exactly the case userSoDViolations' own admin-bypass branch flags
// on the periodic scan. Applying that same rule as a hard PREVENTIVE block would
// refuse ALL further admin-role provisioning the moment any SoD policy exists —
// an availability regression far outside what this fix is meant to close.
// Admin-role grants are separately, adequately gated by their own
// escalation-by-proxy ceiling (requireAuthorityForRole/requireAdminAuthorityAt:
// only an existing admin may grant one).
//
// Also deliberately NOT wired into break_glass.go's self-service emergency
// activation: break-glass is documented as "Deliberately un-gated by RBAC — the
// whole point is access the user does NOT already have", and a false-positive
// SoD block during a genuine incident would be a severe, unacceptable failure
// mode for the control that exists to remediate incidents. See
// assignUserRoleWithExpirySkipSoD (jit_access.go) for the carve-out, which
// mirrors the SAME reasoning this codebase already applies to the ceiling check
// AssignUserRoleWithExpiry also (deliberately) skips.

// sodPolicyNewlyCompletedBy returns the first policy in policies that becomes
// satisfied (both permission sides held) once adding is unioned into held, but
// was NOT already satisfied by held alone — i.e. a violation this specific
// change would newly create, not one that already existed. nil when nothing
// newly completes. The one shared predicate every preventive check below (and,
// via userSoDViolations, the periodic scan) evaluates a policy with.
func sodPolicyNewlyCompletedBy(policies []*models.SoDPolicy, held, adding map[string]bool) *models.SoDPolicy {
	for _, pol := range policies {
		if held[pol.PermissionA] && held[pol.PermissionB] {
			continue // already violated before this change — not created by it
		}
		hasA := held[pol.PermissionA] || adding[pol.PermissionA]
		hasB := held[pol.PermissionB] || adding[pol.PermissionB]
		if hasA && hasB {
			return pol
		}
	}
	return nil
}

// rolePermissionNameSet returns the permission names roleID's role_permissions
// rows carry.
func (c *KeyorixCore) rolePermissionNameSet(ctx context.Context, roleID uint) (map[string]bool, error) {
	perms, err := c.storage.GetRolePermissions(ctx, roleID)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(perms))
	for _, p := range perms {
		set[p.Name] = true
	}
	return set, nil
}

// sodBlockedErr formats the blocking error a preventive check returns when a
// grant would newly complete pol.
func sodBlockedErr(pol *models.SoDPolicy, detail string) error {
	return fmt.Errorf("cannot %s: it would create a separation-of-duties violation with policy %q (%s + %s)",
		detail, pol.Name, pol.PermissionA, pol.PermissionB)
}

// requireNoSoDViolation is the preventive gate for a DIRECT user role grant: it
// blocks granting roleID to userID if doing so would newly complete an SoD
// policy given userID's OTHER current permissions (direct + group,
// scope-agnostic — SoD policies are principal-level, exactly like the periodic
// scan, not scope-restricted; a user must never hold both sides ANYWHERE, not
// merely "not in the same project"). This is the choke point AssignUserRole and
// AssignUserRoleWithExpiry both call.
func (c *KeyorixCore) requireNoSoDViolation(ctx context.Context, userID, roleID uint) error {
	policies, err := c.storage.ListSoDPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}
	if c.adminRoleName(ctx, userID) != "" {
		return nil // already holds admin-bypass — see package doc above
	}
	role, err := c.storage.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if isAdminRoleName(role.Name) {
		return nil // granting admin-bypass — see package doc above
	}
	adding, err := c.rolePermissionNameSet(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if len(adding) == 0 {
		return nil
	}
	held, err := c.userHeldPermissionSet(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if pol := sodPolicyNewlyCompletedBy(policies, held, adding); pol != nil {
		return sodBlockedErr(pol, "grant this role")
	}
	return nil
}

// requireGroupGrantNoSoDViolation is requireNoSoDViolation's GROUP-grant
// counterpart: a role assigned to a group is inherited by every member, so it
// can complete a policy for a member exactly as a direct grant would. Checks
// each active, non-admin-bypass member (a group's membership is a small,
// bounded set — unlike DetectSoDViolations' full-deployment scan — so this
// stays cheap even run synchronously on every group-role assignment). A member
// who already holds admin-bypass is skipped, not treated as a block (see
// package doc above).
func (c *KeyorixCore) requireGroupGrantNoSoDViolation(ctx context.Context, groupID, roleID uint) error {
	policies, err := c.storage.ListSoDPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}
	role, err := c.storage.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if isAdminRoleName(role.Name) {
		return nil
	}
	adding, err := c.rolePermissionNameSet(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if len(adding) == 0 {
		return nil
	}
	members, err := c.storage.ListGroupMembers(ctx, groupID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	for _, m := range members {
		if !m.IsActive || c.adminRoleName(ctx, m.ID) != "" {
			continue
		}
		held, err := c.userHeldPermissionSet(ctx, m.ID)
		if err != nil {
			return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
		}
		if pol := sodPolicyNewlyCompletedBy(policies, held, adding); pol != nil {
			return fmt.Errorf("cannot assign this role to the group: it would create a separation-of-duties violation for member %d with policy %q (%s + %s)",
				m.ID, pol.Name, pol.PermissionA, pol.PermissionB)
		}
	}
	return nil
}

// requireMachineGrantNoSoDViolation is requireNoSoDViolation's machine-identity
// counterpart: a machine holds permissions only through its explicit role
// grants (machineSoDViolations — no admin-bypass ever applies to a machine, a
// leaked token is bounded to its explicit grants), so "held" is simply the
// union of its OTHER current roles' permissions.
func (c *KeyorixCore) requireMachineGrantNoSoDViolation(ctx context.Context, machineID, roleID uint) error {
	policies, err := c.storage.ListSoDPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}
	role, err := c.storage.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if isAdminRoleName(role.Name) {
		return nil
	}
	adding, err := c.rolePermissionNameSet(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if len(adding) == 0 {
		return nil
	}
	roles, err := c.storage.GetMachineRoles(ctx, machineID)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	held := make(map[string]bool)
	for _, r := range roles {
		perms, err := c.rolePermissionNameSet(ctx, r.ID)
		if err != nil {
			return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
		}
		for name := range perms {
			held[name] = true
		}
	}
	if pol := sodPolicyNewlyCompletedBy(policies, held, adding); pol != nil {
		return sodBlockedErr(pol, "assign this role")
	}
	return nil
}

// requireGrantSetNoSoDViolation is requireNoSoDViolation's counterpart for a set
// of roles granted ATOMICALLY to one principal with NO prior grants — e.g.
// CreateUserWithAssignments minting a brand-new user's system role plus project
// assignments in one call, where there is no user ID yet to look up existing
// permissions against, so every role in the set is evaluated together instead.
// Any role in the set that is itself admin-bypass exempts the whole set (see
// package doc above).
func (c *KeyorixCore) requireGrantSetNoSoDViolation(ctx context.Context, roleIDs []uint) error {
	policies, err := c.storage.ListSoDPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
	}
	if len(policies) == 0 {
		return nil
	}
	held := make(map[string]bool)
	for _, rid := range roleIDs {
		role, err := c.storage.GetRole(ctx, rid)
		if err != nil {
			return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
		}
		if isAdminRoleName(role.Name) {
			return nil
		}
		perms, err := c.rolePermissionNameSet(ctx, rid)
		if err != nil {
			return fmt.Errorf("failed to evaluate separation-of-duties policy: %w", err)
		}
		for name := range perms {
			held[name] = true
		}
	}
	if pol := sodPolicyNewlyCompletedBy(policies, map[string]bool{}, held); pol != nil {
		return fmt.Errorf("cannot create user: the combined role assignments would create a separation-of-duties violation with policy %q (%s + %s)",
			pol.Name, pol.PermissionA, pol.PermissionB)
	}
	return nil
}
