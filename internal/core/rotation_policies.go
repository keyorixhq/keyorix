package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type CreateRotationPolicyRequest struct {
	Name            string `json:"name" validate:"required,min=1,max=255"`
	Description     string `json:"description"`
	Scope           string `json:"scope" validate:"required,oneof=project environment"`
	ProjectID       *uint  `json:"project_id"`
	EnvironmentID   *uint  `json:"environment_id"`
	IntervalDays    int    `json:"interval_days" validate:"required,min=1,max=365"`
	AlertDaysBefore int    `json:"alert_days_before" validate:"min=0,max=90"`
	NotifyOnBreach  bool   `json:"notify_on_breach"`
	CreatedBy       string `json:"created_by" validate:"required"`
}

type UpdateRotationPolicyRequest struct {
	ID              uint   `json:"id" validate:"required"`
	Name            string `json:"name" validate:"required,min=1,max=255"`
	Description     string `json:"description"`
	IntervalDays    int    `json:"interval_days" validate:"required,min=1,max=365"`
	AlertDaysBefore int    `json:"alert_days_before" validate:"min=0,max=90"`
	NotifyOnBreach  bool   `json:"notify_on_breach"`
	IsActive        bool   `json:"is_active"`
}

type RotationPolicyEvaluation struct {
	PolicyID      uint       `json:"policy_id"`
	PolicyName    string     `json:"policy_name"`
	SecretID      uint       `json:"secret_id"`
	SecretName    string     `json:"secret_name"`
	ProjectID     uint       `json:"project_id"`
	LastRotatedAt *time.Time `json:"last_rotated_at"`
	DaysOverdue   int        `json:"days_overdue"` // positive = overdue, negative = days remaining
	IsOverdue     bool       `json:"is_overdue"`
	IsApproaching bool       `json:"is_approaching"`
}

func (c *KeyorixCore) CreateRotationPolicy(ctx context.Context, req *CreateRotationPolicyRequest) (*models.RotationPolicy, error) {
	if req.Scope == "environment" && req.EnvironmentID == nil {
		return nil, fmt.Errorf("environment_id is required when scope is 'environment'")
	}
	if req.Scope == "project" && req.ProjectID == nil {
		return nil, fmt.Errorf("project_id is required when scope is 'project'")
	}
	if req.AlertDaysBefore >= req.IntervalDays {
		return nil, fmt.Errorf("alert_days_before must be less than interval_days")
	}

	policy := &models.RotationPolicy{
		Name:            req.Name,
		Description:     req.Description,
		Scope:           req.Scope,
		ProjectID:       req.ProjectID,
		EnvironmentID:   req.EnvironmentID,
		IntervalDays:    req.IntervalDays,
		AlertDaysBefore: req.AlertDaysBefore,
		NotifyOnBreach:  req.NotifyOnBreach,
		IsActive:        true,
		CreatedBy:       req.CreatedBy,
	}

	if err := c.storage.CreateRotationPolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to create rotation policy: %w", err)
	}
	return policy, nil
}

func (c *KeyorixCore) GetRotationPolicy(ctx context.Context, id uint) (*models.RotationPolicy, error) {
	policy, err := c.storage.GetRotationPolicy(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get rotation policy: %w", err)
	}
	return policy, nil
}

func (c *KeyorixCore) ListRotationPolicies(ctx context.Context, projectID *uint, environmentID *uint) ([]*models.RotationPolicy, error) {
	policies, err := c.storage.ListRotationPolicies(ctx, projectID, environmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list rotation policies: %w", err)
	}
	return policies, nil
}

func (c *KeyorixCore) UpdateRotationPolicy(ctx context.Context, req *UpdateRotationPolicyRequest) (*models.RotationPolicy, error) {
	if req.AlertDaysBefore >= req.IntervalDays {
		return nil, fmt.Errorf("alert_days_before must be less than interval_days")
	}

	policy, err := c.storage.GetRotationPolicy(ctx, req.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get rotation policy: %w", err)
	}

	policy.Name = req.Name
	policy.Description = req.Description
	policy.IntervalDays = req.IntervalDays
	policy.AlertDaysBefore = req.AlertDaysBefore
	policy.NotifyOnBreach = req.NotifyOnBreach
	policy.IsActive = req.IsActive

	if err := c.storage.UpdateRotationPolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to update rotation policy: %w", err)
	}
	return policy, nil
}

func (c *KeyorixCore) DeleteRotationPolicy(ctx context.Context, id uint) error {
	if _, err := c.storage.GetRotationPolicy(ctx, id); err != nil {
		return fmt.Errorf("failed to get rotation policy: %w", err)
	}
	if err := c.storage.DeleteRotationPolicy(ctx, id); err != nil {
		return fmt.Errorf("failed to delete rotation policy: %w", err)
	}
	return nil
}

// Rotation status values returned by GetRotationStatus.
const (
	RotationStatusOverdue = "overdue"
	RotationStatusDueSoon = "due_soon"
	RotationStatusOK      = "ok"
)

// RotationStatusEntry is the per-secret rotation posture under a policy. Unlike
// RotationPolicyEvaluation (which only surfaces overdue/approaching secrets),
// GetRotationStatus returns every policy-covered secret with an explicit status,
// so the dashboard can render a full inspector and a rotation health score.
type RotationStatusEntry struct {
	PolicyID          uint       `json:"policy_id"`
	PolicyName        string     `json:"policy_name"`
	IntervalDays      int        `json:"interval_days"`
	AlertDaysBefore   int        `json:"alert_days_before"`
	SecretID          uint       `json:"secret_id"`
	SecretName        string     `json:"secret_name"`
	EnvironmentID     uint       `json:"environment_id"`
	LastRotatedAt     *time.Time `json:"last_rotated_at"`
	DaysSinceRotation int        `json:"days_since_rotation"`
	DaysOverdue       int        `json:"days_overdue"` // positive = overdue, negative = days remaining
	Status            string     `json:"status"`       // overdue | due_soon | ok
}

// GetRotationStatus returns the rotation posture of every secret covered by an
// active rotation policy (optionally scoped to a project), classified as
// overdue / due_soon / ok. Secrets never rotated fall back to their creation
// time, mirroring EvaluateRotationPolicies.
// scopedPolicySecrets returns every secret in a rotation policy's scope, paging
// through all of them. Rotation evaluation must NOT silently cap: a project (or
// environment) with more than one page of secrets would otherwise have the
// secrets past the cap never checked for rotation — so overdue ones would be
// missed by both the reminder scheduler and the status/evaluate views.
func (c *KeyorixCore) scopedPolicySecrets(ctx context.Context, policy *models.RotationPolicy) ([]*models.SecretNode, error) {
	const pageSize = 500
	var projectID, environmentID *uint
	if policy.Scope == "project" {
		projectID = policy.ProjectID
	} else {
		environmentID = policy.EnvironmentID
	}

	var all []*models.SecretNode
	for page := 1; ; page++ {
		secrets, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
			Page: page, PageSize: pageSize, ProjectID: projectID, EnvironmentID: environmentID,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, secrets...)
		if len(secrets) < pageSize || int64(len(all)) >= total {
			break
		}
	}
	return all, nil
}

func (c *KeyorixCore) GetRotationStatus(ctx context.Context, projectID *uint) ([]*RotationStatusEntry, error) {
	policies, err := c.storage.ListRotationPolicies(ctx, projectID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list rotation policies: %w", err)
	}

	var entries []*RotationStatusEntry
	now := c.now()

	for _, policy := range policies {
		if !policy.IsActive {
			continue
		}

		secrets, err := c.scopedPolicySecrets(ctx, policy)
		if err != nil {
			continue
		}

		for _, secret := range secrets {
			lastRotated := secret.CreatedAt
			if secret.LastRotatedAt != nil {
				lastRotated = *secret.LastRotatedAt
			}

			daysSince := int(now.Sub(lastRotated).Hours() / 24)
			daysOverdue := daysSince - policy.IntervalDays

			status := RotationStatusOK
			if daysOverdue > 0 {
				status = RotationStatusOverdue
			} else if (policy.IntervalDays - daysSince) <= policy.AlertDaysBefore {
				status = RotationStatusDueSoon
			}

			entries = append(entries, &RotationStatusEntry{
				PolicyID:          policy.ID,
				PolicyName:        policy.Name,
				IntervalDays:      policy.IntervalDays,
				AlertDaysBefore:   policy.AlertDaysBefore,
				SecretID:          secret.ID,
				SecretName:        secret.Name,
				EnvironmentID:     secret.EnvironmentID,
				LastRotatedAt:     secret.LastRotatedAt,
				DaysSinceRotation: daysSince,
				DaysOverdue:       daysOverdue,
				Status:            status,
			})
		}
	}

	return entries, nil
}

func (c *KeyorixCore) EvaluateRotationPolicies(ctx context.Context, projectID *uint) ([]*RotationPolicyEvaluation, error) {
	policies, err := c.storage.ListRotationPolicies(ctx, projectID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list rotation policies: %w", err)
	}

	var evaluations []*RotationPolicyEvaluation
	now := c.now()

	for _, policy := range policies {
		if !policy.IsActive {
			continue
		}

		secrets, err := c.scopedPolicySecrets(ctx, policy)
		if err != nil {
			continue
		}

		for _, secret := range secrets {
			var lastRotated time.Time
			if secret.LastRotatedAt != nil {
				lastRotated = *secret.LastRotatedAt
			} else {
				lastRotated = secret.CreatedAt
			}

			daysSinceRotation := int(now.Sub(lastRotated).Hours() / 24)
			daysOverdue := daysSinceRotation - policy.IntervalDays
			isOverdue := daysOverdue > 0
			isApproaching := !isOverdue && (policy.IntervalDays-daysSinceRotation) <= policy.AlertDaysBefore

			if isOverdue || isApproaching {
				evaluations = append(evaluations, &RotationPolicyEvaluation{
					PolicyID:      policy.ID,
					PolicyName:    policy.Name,
					SecretID:      secret.ID,
					SecretName:    secret.Name,
					ProjectID:     secret.ProjectID,
					LastRotatedAt: secret.LastRotatedAt,
					DaysOverdue:   daysOverdue,
					IsOverdue:     isOverdue,
					IsApproaching: isApproaching,
				})
			}
		}
	}

	return evaluations, nil
}
