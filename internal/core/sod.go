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

// SoDViolation is one user who effectively holds both permissions a policy forbids
// together.
type SoDViolation struct {
	PolicyID    uint   `json:"policy_id"`
	PolicyName  string `json:"policy_name"`
	UserID      uint   `json:"user_id"`
	Username    string `json:"username"`
	Email       string `json:"email,omitempty"`
	PermissionA string `json:"permission_a"`
	PermissionB string `json:"permission_b"`
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

// DetectSoDViolations evaluates every policy against every active user's effective
// permissions and returns each principal that holds both sides of a policy. Empty
// when there are no policies. It pages through all users (no silent cap).
func (c *KeyorixCore) DetectSoDViolations(ctx context.Context) ([]SoDViolation, error) {
	policies, err := c.storage.ListSoDPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if len(policies) == 0 {
		return []SoDViolation{}, nil
	}

	violations := []SoDViolation{}
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
			perms, err := c.storage.GetUserPermissions(ctx, u.ID)
			if err != nil {
				continue // best-effort; a user whose permissions can't be read is skipped
			}
			held := make(map[string]bool, len(perms))
			for _, p := range perms {
				held[p.Name] = true
			}
			for _, pol := range policies {
				if held[pol.PermissionA] && held[pol.PermissionB] {
					violations = append(violations, SoDViolation{
						PolicyID: pol.ID, PolicyName: pol.Name,
						UserID: u.ID, Username: u.Username, Email: u.Email,
						PermissionA: pol.PermissionA, PermissionB: pol.PermissionB,
					})
				}
			}
		}
		if len(users) < pageSize || int64(page*pageSize) >= total {
			break
		}
	}
	return violations, nil
}

// actorPtr returns a *uint for an actor id (nil when 0/unauthenticated).
func actorPtr(id uint) *uint {
	if id == 0 {
		return nil
	}
	a := id
	return &a
}
