// rotation_state.go — per-policy rotation execution state (idle/pending/rotating/
// succeeded/failed). The rotation executor stamps these fields so operators can
// see stalled or failed rotations via GET /api/v1/secrets/{id}/rotation-state.
package core

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Valid rotation state values.
const (
	RotationStateIdle      = "idle"
	RotationStatePending   = "pending"
	RotationStateRotating  = "rotating"
	RotationStateSucceeded = "succeeded"
	RotationStateFailed    = "failed"
)

// validRotationStates is the exhaustive set of states a RotationPolicy may hold.
var validRotationStates = map[string]bool{
	RotationStateIdle:      true,
	RotationStatePending:   true,
	RotationStateRotating:  true,
	RotationStateSucceeded: true,
	RotationStateFailed:    true,
}

// RotationStateInfo is the response payload for GET /api/v1/secrets/{id}/rotation-state.
type RotationStateInfo struct {
	SecretID          uint       `json:"secret_id"`
	PolicyID          *uint      `json:"policy_id,omitempty"`
	State             string     `json:"state"`
	LastRotationError string     `json:"last_rotation_error,omitempty"`
	LastStateAt       *time.Time `json:"last_state_at,omitempty"`
}

// GetRotationState returns the current rotation execution state for the secret's
// covering rotation policy. If no active policy covers this secret, State is
// RotationStateIdle and PolicyID is nil (not an error).
func (c *KeyorixCore) GetRotationState(ctx context.Context, secretID uint) (*RotationStateInfo, error) {
	policy, err := c.storage.GetRotationPolicyBySecret(ctx, secretID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			// No active policy — idle is the correct answer.
			return &RotationStateInfo{
				SecretID: secretID,
				State:    RotationStateIdle,
			}, nil
		}
		return nil, fmt.Errorf("GetRotationState: %w", err)
	}

	state := policy.RotationState
	if state == "" {
		state = RotationStateIdle
	}

	info := &RotationStateInfo{
		SecretID:          secretID,
		PolicyID:          &policy.ID,
		State:             state,
		LastRotationError: policy.LastRotationError,
		LastStateAt:       policy.LastStateAt,
	}
	return info, nil
}

// SetRotationState stamps the rotation execution state on the given policy.
// Returns a validation error if state is not one of the five valid values.
// Called by the rotation executor when a rotation job starts, completes, or fails.
func (c *KeyorixCore) SetRotationState(ctx context.Context, policyID uint, state, errMsg string) error {
	if !validRotationStates[state] {
		return fmt.Errorf("invalid rotation state %q: must be one of idle, pending, rotating, succeeded, failed", state)
	}
	if err := c.storage.UpdateRotationState(ctx, policyID, state, errMsg); err != nil {
		if strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("SetRotationState: rotation policy %d not found", policyID)
		}
		return fmt.Errorf("SetRotationState: %w", err)
	}
	return nil
}
