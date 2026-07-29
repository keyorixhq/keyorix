package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStepUpGate_BothFlagsOff_NoGating verifies that checkRestrictedSecretReadApproval
// is a no-op when no gate flags are active.
func TestStepUpGate_BothFlagsOff_NoGating(t *testing.T) {
	c, _, _ := newMFATestCore(t)
	ctx := context.Background()

	// No gate flags set — should never return an error regardless of user or secret.
	secret := &models.SecretNode{Name: "db-pass", Classification: ClassificationRestricted}
	err := c.checkRestrictedSecretReadApproval(ctx, secret, 1)
	require.NoError(t, err, "no gate active: must be a no-op for any user")
}

// TestStepUpGate_On_NoActiveGrant_Denied verifies that with the MFA step-up gate
// enabled and no grant present, access to a restricted secret is denied.
func TestStepUpGate_On_NoActiveGrant_Denied(t *testing.T) {
	c, _, _ := newMFATestCore(t)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresMFAStepUp(true, 0)

	secret := &models.SecretNode{Name: "db-pass", Classification: ClassificationRestricted}
	err := c.checkRestrictedSecretReadApproval(ctx, secret, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restricted")
	assert.Contains(t, err.Error(), "MFA")
}

// TestStepUpGate_On_ActiveGrant_Allowed verifies that a user with a valid
// (non-expired) MFAStepUpGrant can pass the gate.
func TestStepUpGate_On_ActiveGrant_Allowed(t *testing.T) {
	c, db, fixed := newMFATestCore(t)
	ctx := context.Background()
	c.SetClassificationRestrictedRequiresMFAStepUp(true, 0)

	// Seed an active step-up grant relative to the fixed clock.
	future := fixed.Add(15 * time.Minute)
	require.NoError(t, db.Create(&models.MFAStepUpGrant{UserID: 1, ExpiresAt: future}).Error)

	secret := &models.SecretNode{Name: "db-pass", Classification: ClassificationRestricted}
	err := c.checkRestrictedSecretReadApproval(ctx, secret, 1)
	require.NoError(t, err, "active MFA step-up grant must let the gate pass")
}

// TestStepUpGate_LowerClassification_NeverGated verifies that the MFA step-up gate
// only applies to "restricted" classified secrets and leaves lower tiers alone.
func TestStepUpGate_LowerClassification_NeverGated(t *testing.T) {
	for _, level := range []string{ClassificationPublic, ClassificationInternal, ClassificationConfidential, ""} {
		t.Run("classification="+level, func(t *testing.T) {
			c, _, _ := newMFATestCore(t)
			ctx := context.Background()
			c.SetClassificationRestrictedRequiresMFAStepUp(true, 0)

			// No step-up grant seeded — but the gate must not trigger for lower tiers.
			secret := &models.SecretNode{Name: "db-pass", Classification: level}
			err := c.checkRestrictedSecretReadApproval(ctx, secret, 1)
			require.NoError(t, err, "MFA step-up gate must not apply to %q-classified secrets", level)
		})
	}
}
