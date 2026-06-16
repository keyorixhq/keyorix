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

	"github.com/keyorixhq/keyorix/internal/rotation"
)

// SetRotationManager wires the configured backend rotation executors (ADR-047) that
// apply a new credential to an upstream system. nil (the default) leaves backend
// rotation disabled — auto-rotation then only regenerates Keyorix-owned values.
func (c *KeyorixCore) SetRotationManager(m *rotation.Manager) {
	c.rotationManager = m
}

// RotationBackendNames lists the configured rotation-backend names (for discovery).
func (c *KeyorixCore) RotationBackendNames() []string {
	if c.rotationManager == nil {
		return nil
	}
	return c.rotationManager.Names()
}

// Audit events for automated rotation (ADR-046).
const (
	EventSecretAutoRotated      = "secret.auto_rotated"
	EventSecretAutoRotateConfig = "secret.auto_rotate_configured"
)

// Default generated value: 32 chars over a 62-symbol alphanumeric set (~190 bits).
// Alphanumeric so a consumer reading it back never trips over shell/URL metacharacters.
const (
	rotatedValueLength    = 32
	rotatedValueMinLength = 8
	rotatedValueMaxLength = 256
)

// Named charsets a secret may select via RotationCharset (ADR-046). "" = alphanumeric.
const (
	charsetAlphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	charsetLowerAlnum   = "abcdefghijklmnopqrstuvwxyz0123456789"
	charsetHex          = "0123456789abcdef"
	charsetAlnumSymbols = charsetAlphanumeric + "!@#$%^&*-_=+"
	rotatedValueCharset = charsetAlphanumeric // back-compat alias (default)
)

// resolveCharset maps a RotationCharset name to its character set, defaulting to
// alphanumeric for "" or an unknown name (fail-safe: never an empty alphabet).
func resolveCharset(name string) string {
	switch name {
	case "lower_alphanumeric":
		return charsetLowerAlnum
	case "hex":
		return charsetHex
	case "alphanumeric_symbols":
		return charsetAlnumSymbols
	default:
		return charsetAlphanumeric
	}
}

// resolveLength clamps a requested length into [min,max], defaulting to 32 for 0.
func resolveLength(n int) int {
	if n <= 0 {
		return rotatedValueLength
	}
	if n < rotatedValueMinLength {
		return rotatedValueMinLength
	}
	if n > rotatedValueMaxLength {
		return rotatedValueMaxLength
	}
	return n
}

// generateRotatedValue returns a fresh random value of the default shape (crypto/rand).
func generateRotatedValue() (string, error) {
	return generateRotatedValueSpec(0, "")
}

// generateRotatedValueSpec returns a fresh random value of the requested length and
// charset (crypto/rand), applying the defaults/clamping above.
func generateRotatedValueSpec(length int, charset string) (string, error) {
	n := resolveLength(length)
	set := resolveCharset(charset)
	b := make([]byte, n)
	for i := range b {
		ch, err := randChar(set)
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

			val, gerr := generateRotatedValueSpec(secret.RotationLength, secret.RotationCharset)
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

// knownRotationCharset reports whether name is a recognized charset (or "" = default).
func knownRotationCharset(name string) bool {
	switch name {
	case "", "alphanumeric", "lower_alphanumeric", "hex", "alphanumeric_symbols":
		return true
	default:
		return false
	}
}

// SetSecretAutoRotate enables or disables automated rotation for a secret and sets the
// generated-value shape (length 0 = default, charset "" = default alphanumeric), then
// audits the change. Enable only for secrets whose value Keyorix owns (see file header).
func (c *KeyorixCore) SetSecretAutoRotate(ctx context.Context, id uint, enabled bool, length int, charset string, actorID uint) error {
	if !knownRotationCharset(charset) {
		return fmt.Errorf("unknown rotation charset %q (want alphanumeric|lower_alphanumeric|hex|alphanumeric_symbols)", charset)
	}
	if length != 0 && (length < rotatedValueMinLength || length > rotatedValueMaxLength) {
		return fmt.Errorf("rotation length %d out of range (%d–%d, or 0 for default)", length, rotatedValueMinLength, rotatedValueMaxLength)
	}
	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}
	secret.AutoRotate = enabled
	secret.RotationLength = length
	secret.RotationCharset = charset
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
