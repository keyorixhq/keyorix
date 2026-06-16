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
	"github.com/keyorixhq/keyorix/internal/storage/models"
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
			// Backend rotation (ADR-047): if the secret names a configured executor,
			// apply the new value UPSTREAM first. Only on success do we store it in
			// Keyorix, so the two never drift. A backend that is named but unconfigured
			// or whose upstream apply fails is skipped (logged + audited), not stored.
			if secret.RotationBackend != "" {
				if err := c.applyBackendRotation(ctx, secret, val); err != nil {
					sid := secret.ID
					c.writeAuditEvent(ctx, EventSecretAutoRotated, nil, &sid,
						fmt.Sprintf("auto-rotation FAILED for secret %q via backend %q ref %q: %v", secret.Name, secret.RotationBackend, secret.RotationRef, err))
					log.Printf("auto-rotation: backend rotate secret %d: %v", secret.ID, err)
					continue
				}
			}
			if _, rerr := c.RotateSecret(ctx, secret.ID, []byte(val), "system:auto-rotation"); rerr != nil {
				log.Printf("auto-rotation: rotate secret %d: %v", secret.ID, rerr)
				continue
			}
			done[secret.ID] = true
			rotated++
			sid := secret.ID
			via := ""
			if secret.RotationBackend != "" {
				via = fmt.Sprintf(" via backend %q ref %q", secret.RotationBackend, secret.RotationRef)
			}
			c.writeAuditEvent(ctx, EventSecretAutoRotated, nil, &sid,
				fmt.Sprintf("auto-rotated secret %q (policy %q, interval %dd)%s", secret.Name, policy.Name, policy.IntervalDays, via))
		}
	}
	return rotated, nil
}

// applyBackendRotation resolves the secret's named rotation executor and applies
// newValue to the upstream credential (ADR-047). Returns an error (so the caller does
// NOT store the value) when no backend manager is configured, the named backend is
// unknown, or the upstream apply fails.
func (c *KeyorixCore) applyBackendRotation(ctx context.Context, secret *models.SecretNode, newValue string) error {
	if c.rotationManager == nil {
		return fmt.Errorf("no rotation backends configured")
	}
	exec, ok := c.rotationManager.Get(secret.RotationBackend)
	if !ok {
		return fmt.Errorf("unknown rotation backend %q", secret.RotationBackend)
	}
	if secret.RotationRef == "" {
		return fmt.Errorf("rotation_ref is required for backend rotation")
	}
	return exec.Rotate(ctx, secret.RotationRef, newValue)
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

// AutoRotateSpec is the per-secret automated-rotation configuration set via
// SetSecretAutoRotate (ADR-046/047). Length 0 = default; Charset "" = default
// alphanumeric. Backend "" = regenerate in Keyorix only; when Backend names a
// configured executor, Ref is the upstream identifier it rotates (required iff Backend
// is set).
type AutoRotateSpec struct {
	Enabled bool
	Length  int
	Charset string
	Backend string
	Ref     string
}

// SetSecretAutoRotate configures automated rotation for a secret and audits the change.
// Enable only for secrets whose value Keyorix owns, OR point Backend at an executor that
// rotates the upstream credential too (ADR-047). The caller (transport) must have
// enforced scoped secrets.write.
func (c *KeyorixCore) SetSecretAutoRotate(ctx context.Context, id uint, spec AutoRotateSpec, actorID uint) error {
	if !knownRotationCharset(spec.Charset) {
		return fmt.Errorf("unknown rotation charset %q (want alphanumeric|lower_alphanumeric|hex|alphanumeric_symbols)", spec.Charset)
	}
	if spec.Length != 0 && (spec.Length < rotatedValueMinLength || spec.Length > rotatedValueMaxLength) {
		return fmt.Errorf("rotation length %d out of range (%d–%d, or 0 for default)", spec.Length, rotatedValueMinLength, rotatedValueMaxLength)
	}
	// Backend and ref are both-or-neither: a backend with no ref can't be applied, and a
	// ref with no backend is meaningless.
	if (spec.Backend == "") != (spec.Ref == "") {
		return fmt.Errorf("rotation_backend and rotation_ref must be set together (or both empty)")
	}
	secret, err := c.storage.GetSecret(ctx, id)
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}
	secret.AutoRotate = spec.Enabled
	secret.RotationLength = spec.Length
	secret.RotationCharset = spec.Charset
	secret.RotationBackend = spec.Backend
	secret.RotationRef = spec.Ref
	secret.UpdatedAt = c.now()
	if _, err := c.storage.UpdateSecret(ctx, secret); err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}
	uid := actorID
	sid := id
	verb := "disabled"
	if spec.Enabled {
		verb = "enabled"
	}
	via := ""
	if spec.Backend != "" {
		via = fmt.Sprintf(" (backend %q ref %q)", spec.Backend, spec.Ref)
	}
	c.writeAuditEvent(ctx, EventSecretAutoRotateConfig, &uid, &sid,
		fmt.Sprintf("auto-rotation %s for secret %q%s", verb, secret.Name, via))
	return nil
}
