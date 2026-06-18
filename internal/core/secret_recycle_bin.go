// secret_recycle_bin.go — the recycle bin: list a project's soft-deleted (restorable)
// secrets so an operator can discover what to restore. Secrets soft-delete on DELETE
// (ADR-033) and are reaped by the purge job after the retention window; until then a
// restore is possible, but the restore route needs the secret's ID — which, without
// this view, an operator has no way to find. Read-only and metadata-only: it never
// returns or touches a secret value. Project-scoped (route-gated secrets.read).
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// defaultRecycleBinLimit bounds the trash listing when no limit is given.
const defaultRecycleBinLimit = 100

// maxRecycleBinLimit caps a single trash page.
const maxRecycleBinLimit = 500

// ListDeletedSecrets returns the project's soft-deleted secrets, most-recently-deleted
// first, for the restore UI. `limit` is clamped to [1, maxRecycleBinLimit]; a
// non-positive limit falls back to defaultRecycleBinLimit. Returns metadata only.
func (c *KeyorixCore) ListDeletedSecrets(ctx context.Context, projectID uint, limit int) ([]*models.SecretNode, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}
	if limit <= 0 {
		limit = defaultRecycleBinLimit
	}
	if limit > maxRecycleBinLimit {
		limit = maxRecycleBinLimit
	}
	secrets, _, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
		ProjectID:   &projectID,
		DeletedOnly: true,
		Page:        1,
		PageSize:    limit,
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	// Already newest-deleted first (ordered in the storage query, before LIMIT).
	return secrets, nil
}
