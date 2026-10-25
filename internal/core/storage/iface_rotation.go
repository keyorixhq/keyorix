package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// RotationStore is the Storage slice for rotation policies and state.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type RotationStore interface {
	// Rotation Policy Management
	CreateRotationPolicy(ctx context.Context, p *models.RotationPolicy) error
	GetRotationPolicy(ctx context.Context, id uint) (*models.RotationPolicy, error)
	// GetRotationPolicyBySecret returns the first active rotation policy that covers
	// the secret (by matching the secret's project_id and/or environment_id). Returns
	// ErrNotFound (via the store package) when no policy exists for the secret.
	GetRotationPolicyBySecret(ctx context.Context, secretID uint) (*models.RotationPolicy, error)
	ListRotationPolicies(ctx context.Context, projectID *uint, environmentID *uint) ([]*models.RotationPolicy, error)
	// UpdateRotationPolicyFields persists ONLY the six operator-editable columns
	// named by f (plus updated_at), onto a LIVE policy row. matched=false (no
	// error) means the policy is gone; the caller must not report success.
	//
	// This REPLACES the former UpdateRotationPolicy, a bare GORM Save (#2700),
	// which got two things wrong at once. RotationPolicy IS soft-deletable, so
	// the 0-rows upsert fallback wrote deleted_at = NULL and a stale edit brought
	// a deleted policy back ACTIVE — resuming rotation and breach alerts although
	// the delete had reported success. And the full-row write reverted
	// rotation_state / last_rotation_error / last_state_at, which belong to
	// UpdateRotationState (the executor), hiding a failed rotation; those three
	// columns are deliberately absent from this method.
	UpdateRotationPolicyFields(ctx context.Context, id uint, f RotationPolicyFieldUpdate, updatedAt time.Time) (matched bool, err error)
	DeleteRotationPolicy(ctx context.Context, id uint) error
	// UpdateRotationState stamps the execution state on a RotationPolicy row.
	// state must be one of: idle, pending, rotating, succeeded, failed.
	UpdateRotationState(ctx context.Context, policyID uint, state, errMsg string) error
}
