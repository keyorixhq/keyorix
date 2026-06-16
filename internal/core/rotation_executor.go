// rotation_executor.go — automated secret rotation (ADR-046). Rotation policies say
// WHEN a secret should rotate and reminders nudge admins; this executor actually
// rotates the secrets that opted in (SecretNode.AutoRotate) by regenerating their
// value when they are overdue under an active covering policy.
//
// Only auto-rotate-enabled secrets are touched, and the new value is a freshly
// generated random string — so this is for secrets whose value Keyorix owns. A secret
// that mirrors an external system's credential must NOT enable auto-rotation, since
// regenerating it here does not update the upstream.
package core

import (
	"context"
	"fmt"
	"log"
)

// Audit events for automated rotation (ADR-046).
const (
	EventSecretAutoRotated      = "secret.auto_rotated"
	EventSecretAutoRotateConfig = "secret.auto_rotate_configured"
)

// rotatedValueLength / rotatedValueCharset define the generated value: 32 chars over a
// 62-symbol alphanumeric set (~190 bits of entropy). Alphanumeric only, so a consumer
// that reads the value back never trips over shell/URL metacharacters.
const (
	rotatedValueLength  = 32
	rotatedValueCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// generateRotatedValue returns a fresh random secret value (crypto/rand).
func generateRotatedValue() (string, error) {
	b := make([]byte, rotatedValueLength)
	for i := range b {
		ch, err := randChar(rotatedValueCharset)
		if err != nil {
			return "", err
		}
		b[i] = ch
	}
	return string(b), nil
}

// RunAutoRotation rotates every auto-rotate-enabled secret that is overdue under an
// active rotation policy, regenerating its value (a new version) and auditing each
// rotation. Best-effort per secret: a generate/rotate failure is logged and skipped,
// never aborting the run. A secret covered by multiple policies is rotated at most once
// per run. Returns the number of secrets rotated.
func (c *KeyorixCore) RunAutoRotation(ctx context.Context) (int, error) {
	policies, err := c.storage.ListRotationPolicies(ctx, nil, nil)
	if err != nil {
		return 0, fmt.Errorf("auto-rotation: list policies: %w", err)
	}
	now := c.now()
	rotated := 0
	done := make(map[uint]bool)

	for _, policy := range policies {
		if !policy.IsActive {
			continue
		}
		secrets, err := c.scopedPolicySecrets(ctx, policy)
		if err != nil {
			continue
		}
		for _, secret := range secrets {
			if !secret.AutoRotate || done[secret.ID] {
				continue
			}
			lastRotated := secret.CreatedAt
			if secret.LastRotatedAt != nil {
				lastRotated = *secret.LastRotatedAt
			}
			daysSince := int(now.Sub(lastRotated).Hours() / 24)
			if daysSince < policy.IntervalDays {
				continue // not yet due under this policy
			}

			val, gerr := generateRotatedValue()
			if gerr != nil {
				log.Printf("auto-rotation: generate value for secret %d: %v", secret.ID, gerr)
				continue
			}
			if _, rerr := c.RotateSecret(ctx, secret.ID, []byte(val), "system:auto-rotation"); rerr != nil {
				log.Printf("auto-rotation: rotate secret %d: %v", secret.ID, rerr)
				continue
			}
			done[secret.ID] = true
			rotated++
			sid := secret.ID
			c.writeAuditEvent(ctx, EventSecretAutoRotated, nil, &sid,
				fmt.Sprintf("auto-rotated secret %q (policy %q, interval %dd)", secret.Name, policy.Name, policy.IntervalDays))
		}
	}
	return rotated, nil
}

// SetSecretAutoRotate enables or disables automated rotation for a secret and audits
// the change. Enable only for secrets whose value Keyorix owns (see the file header).
func (c *KeyorixCore) SetSecretAutoRotate(ctx context.Context, id uint, enabled bool, actorID uint) error {
	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}
	secret.AutoRotate = enabled
	secret.UpdatedAt = c.now()
	if _, err := c.storage.UpdateSecret(ctx, secret); err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}
	uid := actorID
	sid := id
	verb := "disabled"
	if enabled {
		verb = "enabled"
	}
	c.writeAuditEvent(ctx, EventSecretAutoRotateConfig, &uid, &sid,
		fmt.Sprintf("auto-rotation %s for secret %q", verb, secret.Name))
	return nil
}
