// secret_description.go — an optional free-text note on a secret (what it's for, which
// upstream it belongs to, who to contact). Pure metadata: it is never the value and is
// readable by anyone who can read the secret. Set requires write on the secret and is
// audited. Settable at creation (CreateSecretRequest.Description) or later via this.
package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// maxSecretDescriptionLen bounds the free-text note.
const maxSecretDescriptionLen = 1024

// validateDescription bounds a free-text description for governance entities
// (projects, groups, rotation policies), matching the secret-description cap, so a
// metadata field can't be used to bloat storage. Empty is allowed.
func validateDescription(description string) error {
	if len(strings.TrimSpace(description)) > maxSecretDescriptionLen {
		return fmt.Errorf("description exceeds %d characters", maxSecretDescriptionLen)
	}
	return nil
}

// SetSecretDescription sets (or clears, with "") the secret's description. The actor
// must be able to write the secret. The note is trimmed and length-bounded. Audited.
func (c *KeyorixCore) SetSecretDescription(ctx context.Context, actorID, secretID uint, description string) (*models.SecretNode, error) {
	if _, err := c.EnforceSecretWritePermission(ctx, secretID, actorID); err != nil {
		return nil, err
	}
	desc := strings.TrimSpace(description)
	if len(desc) > maxSecretDescriptionLen {
		return nil, fmt.Errorf("%s: description exceeds %d characters", i18n.T("ErrorValidation", nil), maxSecretDescriptionLen)
	}
	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if secret.Description == desc {
		return secret, nil // no-op
	}
	secret.Description = desc
	secret.UpdatedAt = c.now()
	updated, err := c.storage.UpdateSecret(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	uid := actorID
	sid := secretID
	c.writeAuditEvent(ctx, "secret.description_updated", &uid, &sid,
		fmt.Sprintf("updated description of secret %d", secretID))
	return updated, nil
}
