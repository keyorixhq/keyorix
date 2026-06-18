// secret_access_history.go — per-secret access history: the recent reads of a secret
// (who, when, from where). Complements the access inspector (who CAN read) with who
// HAS read — an investigation aid. Read-only; the caller must be able to read the
// secret. Returns access-log metadata only (accessor, IP, user-agent, time, action),
// never any secret value.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListSecretAccessHistory returns the secret's access-log entries since `since`. The
// actor must be able to read the secret.
func (c *KeyorixCore) ListSecretAccessHistory(ctx context.Context, secretID, actorID uint, since time.Time) ([]models.SecretAccessLog, error) {
	if _, err := c.EnforceSecretReadPermission(ctx, secretID, actorID); err != nil {
		return nil, err
	}
	logs, err := c.storage.ListSecretAccessLogs(ctx, secretID, since)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return logs, nil
}
