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

	"github.com/keyorixhq/keyorix/internal/core/storage"
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
	updated, err := c.transferOwnership(ctx, secretID, newOwnerID, actorID)
	if err != nil {
		return nil, err
	}
	// Tell the new owner they now own it (single transfer). Bulk reassignment uses
	// transferOwnership directly and sends one summary instead. Best-effort.
	c.notifySecretOwnershipTransferred(ctx, updated, newOwnerID, actorID)
	return updated, nil
}

// transferOwnership performs the validated, audited ownership change without the
// new-owner notification — the shared primitive for single and bulk transfer.
func (c *KeyorixCore) transferOwnership(ctx context.Context, secretID, newOwnerID, actorID uint) (*models.SecretNode, error) {
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

	// The NEW owner must already have access to the secret's scope. Ownership grants
	// full control (incl. re-share), so without this an authorized writer could hand a
	// secret to a user with no role in its project — granting access out of band.
	// Evaluate the new owner's OWN roles, not gated by the actor's PAT restriction.
	if ok, perr := c.principalHasScopedPermission(ctx, newOwnerID, "secrets.read",
		Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}); perr != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), perr)
	} else if !ok {
		return nil, fmt.Errorf("%s: the new owner has no access to this secret's project/environment", i18n.T("ErrorPermissionDenied", nil))
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

// currentOwnerGone reports whether a secret's owner is positively absent: ownerless
// (0) or an account confirmed not to exist. It FAILS CLOSED — a transient GetUser
// error returns false (owner assumed present), so a non-owner cannot ride a momentary
// lookup failure into seizing an actively-owned secret. Only a confirmed "not found"
// counts as "gone" — checked under BOTH storage backends (#504 sibling): LocalStorage
// wraps the typed ErrUserNotFound sentinel, while RemoteStorage instead returns a
// remote.HTTPError; matching the sentinel alone (via errors.Is) silently never
// recognized a gone owner under storage.type: remote, which — since this still fails
// closed — only meant a legitimately recoverable secret couldn't be recovered, not a
// security regression, but was worth closing alongside the rest of #504.
func (c *KeyorixCore) currentOwnerGone(ctx context.Context, ownerID uint) bool {
	if ownerID == 0 {
		return true
	}
	_, err := c.storage.GetUser(ctx, ownerID)
	return storage.IsUserNotFound(err)
}
