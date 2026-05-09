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

		filter := &storage.SecretFilter{Page: 1, PageSize: 1000}
		if policy.Scope == "project" {
			filter.ProjectID = policy.ProjectID
		} else {
			filter.EnvironmentID = policy.EnvironmentID
		}

		secrets, _, err := c.storage.ListSecrets(ctx, filter)
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
