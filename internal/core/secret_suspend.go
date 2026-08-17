// secret_suspend.go — suspend/resume a secret. Suspending blocks value reads (an
// incident-response control: a suspected-compromised secret can be frozen without
// deleting it, preserving its versions, shares, and audit trail) and is reversible.
// Metadata, listing, and management operations stay available so the secret can be
// inspected, rotated, or resumed while suspended.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
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
	fromStatus := secret.Status
	secret.Status = SecretStatusSuspended
	secret.UpdatedAt = c.now()
	matched, err := c.storage.TransitionSecretStatus(ctx, secret, fromStatus)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if !matched {
		// Lost the race: the row's persisted status moved away from fromStatus
		// between the GetSecret read above and this write (a concurrent
		// suspend/resume, or any other concurrent writer of this row) — treat
		// as a failed write rather than silently overwriting the winner.
		return nil, fmt.Errorf("secret %d's status changed concurrently; retry", secretID)
	}
	uid, sid := actorID, secretID
	desc := fmt.Sprintf("suspended secret %q", secret.Name)
	if reason != "" {
		desc += ": " + reason
	}
	c.writeAuditEvent(ctx, EventSecretSuspended, &uid, &sid, desc)
	return secret, nil
}

const projectSuspendPageSize = 500

// SuspendProjectSecrets freezes value reads of every active secret in a project (a
// breach-response "freeze the project" action) and returns how many it suspended.
// Already-suspended secrets are left untouched; a per-secret failure (including a
// per-secret authorization denial — see the EnforceSecretWritePermission re-check
// below) is skipped so one bad secret doesn't abort the freeze. The caller must have
// enforced scoped secrets.write on the project.
func (c *KeyorixCore) SuspendProjectSecrets(ctx context.Context, projectID, actorID uint, reason string) (int, error) {
	if projectID == 0 || actorID == 0 {
		return 0, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID and actor ID are required")
	}
	secrets, err := c.listProjectSecrets(ctx, projectID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range secrets {
		if s.Status == SecretStatusSuspended {
			continue
		}
		// Re-check per-secret write authorization (owner/share). The project-wide
		// secrets.write route gate is not sufficient on its own — the single-secret PUT
		// path enforces this too, so a caller who can't update a secret individually must
		// not be able to via the bulk op (mirrors ExtendExpiringSecrets). Skip (don't
		// abort) on denial.
		if _, err := c.EnforceSecretWritePermission(ctx, s.ID, actorID); err != nil {
			continue
		}
		if _, err := c.SuspendSecret(ctx, s.ID, actorID, reason); err == nil {
			n++
		}
	}
	return n, nil
}

// ResumeProjectSecrets restores value reads of every suspended secret in a project and
// returns how many it resumed. See SuspendProjectSecrets for semantics.
func (c *KeyorixCore) ResumeProjectSecrets(ctx context.Context, projectID, actorID uint) (int, error) {
	if projectID == 0 || actorID == 0 {
		return 0, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID and actor ID are required")
	}
	secrets, err := c.listProjectSecrets(ctx, projectID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range secrets {
		if s.Status != SecretStatusSuspended {
			continue
		}
		// Re-check per-secret write authorization — see the matching check in
		// SuspendProjectSecrets above.
		if _, err := c.EnforceSecretWritePermission(ctx, s.ID, actorID); err != nil {
			continue
		}
		if _, err := c.ResumeSecret(ctx, s.ID, actorID); err == nil {
			n++
		}
	}
	return n, nil
}

// listProjectSecrets pages through every secret in a project.
func (c *KeyorixCore) listProjectSecrets(ctx context.Context, projectID uint) ([]*models.SecretNode, error) {
	pid := projectID
	var all []*models.SecretNode
	for page := 1; ; page++ {
		secrets, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
			ProjectID: &pid, Page: page, PageSize: projectSuspendPageSize,
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
		}
		all = append(all, secrets...)
		if len(secrets) < projectSuspendPageSize || int64(len(all)) >= total {
			break
		}
	}
	return all, nil
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
	fromStatus := secret.Status
	secret.Status = SecretStatusActive
	secret.UpdatedAt = c.now()
	matched, err := c.storage.TransitionSecretStatus(ctx, secret, fromStatus)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if !matched {
		// Lost the race: the row's persisted status moved away from fromStatus
		// between the GetSecret read above and this write (a concurrent
		// suspend/resume, or any other concurrent writer of this row) — treat
		// as a failed write rather than silently overwriting the winner.
		return nil, fmt.Errorf("secret %d's status changed concurrently; retry", secretID)
	}
	uid, sid := actorID, secretID
	c.writeAuditEvent(ctx, EventSecretResumed, &uid, &sid, fmt.Sprintf("resumed secret %q", secret.Name))
	return secret, nil
}
