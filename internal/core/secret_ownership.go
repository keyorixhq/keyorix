// secret_ownership.go — transfer a secret's ownership to another user. A secret's
// owner is the only principal that can manage/share it (CheckSecretPermission grants
// PermissionOwner only to the owner), so when an owner leaves the org their secrets
// are effectively orphaned. Transfer hands ownership to another user — either by the
// current owner, or (for recovery) by any authorized writer when the current owner is
// gone (ownerless or a deleted account).
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// EventSecretOwnerTransferred is audited when a secret's ownership changes hands.
const EventSecretOwnerTransferred = "secret.owner_transferred"

// TransferSecretOwnership sets secretID's owner to newOwnerID. The caller (transport)
// must have enforced scoped secrets.write. Authorization here: the actor must be the
// current owner, OR the current owner must be gone (ownerless, or an account that no
// longer exists) — so an active owner's secret can't be taken from under them, while a
// departed owner's secrets can be recovered. newOwnerID must be an existing user.
func (c *KeyorixCore) TransferSecretOwnership(ctx context.Context, secretID, newOwnerID, actorID uint) (*models.SecretNode, error) {
	if secretID == 0 || newOwnerID == 0 || actorID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret ID, new owner ID and actor ID are required")
	}

	secret, err := c.storage.GetSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	if secret.OwnerID == newOwnerID {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "secret is already owned by that user")
	}
	if _, err := c.storage.GetUser(ctx, newOwnerID); err != nil {
		return nil, fmt.Errorf("%s: new owner %d not found", i18n.T("ErrorValidation", nil), newOwnerID)
	}

	// Authorize: the current owner may hand it off; otherwise it must be ownerless or
	// owned by an account that no longer exists (recovery).
	if !secretOwnedBy(secret.OwnerID, actorID) && !c.currentOwnerGone(ctx, secret.OwnerID) {
		return nil, fmt.Errorf("%s: only the current owner can transfer this secret", i18n.T("ErrorPermissionDenied", nil))
	}

	oldOwner := secret.OwnerID
	secret.OwnerID = newOwnerID
	updated, err := c.storage.UpdateSecret(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	uid := actorID
	sid := secretID
	c.writeAuditEvent(ctx, EventSecretOwnerTransferred, &uid, &sid,
		fmt.Sprintf("transferred ownership of secret %q from user %d to user %d", updated.Name, oldOwner, newOwnerID))
	return updated, nil
}

// currentOwnerGone reports whether a secret's owner is absent: ownerless (0) or an
// account that no longer exists.
func (c *KeyorixCore) currentOwnerGone(ctx context.Context, ownerID uint) bool {
	if ownerID == 0 {
		return true
	}
	u, err := c.storage.GetUser(ctx, ownerID)
	return err != nil || u == nil
}
