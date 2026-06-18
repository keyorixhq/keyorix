// secret_suspend.go — suspend/resume a secret. Suspending blocks value reads (an
// incident-response control: a suspected-compromised secret can be frozen without
// deleting it, preserving its versions, shares, and audit trail) and is reversible.
// Metadata, listing, and management operations stay available so the secret can be
// inspected, rotated, or resumed while suspended.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Secret lifecycle statuses.
const (
	SecretStatusActive    = "active"
	SecretStatusSuspended = "suspended"
)

// Audit event types for suspend/resume.
const (
	EventSecretSuspended = "secret.suspended"
	EventSecretResumed   = "secret.resumed"
)

// SuspendSecret freezes value reads of a secret (idempotent). The caller (transport)
// must have enforced scoped secrets.write.
func (c *KeyorixCore) SuspendSecret(ctx context.Context, secretID, actorID uint, reason string) (*models.SecretNode, error) {
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if secret.Status == SecretStatusSuspended {
		return secret, nil // already suspended — no-op, no duplicate audit
	}
	secret.Status = SecretStatusSuspended
	secret.UpdatedAt = c.now()
	updated, err := c.storage.UpdateSecret(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	uid, sid := actorID, secretID
	desc := fmt.Sprintf("suspended secret %q", updated.Name)
	if reason != "" {
		desc += ": " + reason
	}
	c.writeAuditEvent(ctx, EventSecretSuspended, &uid, &sid, desc)
	return updated, nil
}

// ResumeSecret restores value reads of a suspended secret (idempotent).
func (c *KeyorixCore) ResumeSecret(ctx context.Context, secretID, actorID uint) (*models.SecretNode, error) {
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if secret.Status != SecretStatusSuspended {
		return secret, nil // not suspended — no-op
	}
	secret.Status = SecretStatusActive
	secret.UpdatedAt = c.now()
	updated, err := c.storage.UpdateSecret(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	uid, sid := actorID, secretID
	c.writeAuditEvent(ctx, EventSecretResumed, &uid, &sid, fmt.Sprintf("resumed secret %q", updated.Name))
	return updated, nil
}
