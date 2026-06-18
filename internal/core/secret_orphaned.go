// secret_orphaned.go — orphaned-secret detection: a project's secrets whose owner is
// no longer a live user (the owner was offboarded / deleted). The natural companion to
// ownership transfer ([[secret_ownership]]): this finds the secrets that need
// re-assigning so no secret is left without an accountable owner. Read-only and
// metadata-only — it never returns a secret value. Project-scoped (route-gated).
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListOrphanedSecrets returns the project's live secrets whose owner is no longer a
// live user — offboarding hygiene, so an admin can transfer ownership. Metadata only.
func (c *KeyorixCore) ListOrphanedSecrets(ctx context.Context, projectID uint) ([]*models.SecretNode, error) {
	if projectID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID is required")
	}
	secrets, err := c.storage.ListOrphanedSecrets(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return secrets, nil
}
