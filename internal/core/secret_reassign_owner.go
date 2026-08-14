// secret_reassign_owner.go — bulk owner reassignment: hand every secret a departing
// user owned in a project to a new owner in one call. Completes the offboarding
// workflow — [[secret_orphaned]] finds the secrets a gone owner left behind, this
// re-homes them. Each secret goes through the single-secret transfer, so the same
// authorization (actor is the current owner, or the owner is gone) and the same
// per-secret audit event apply to every one.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// ReassignOwnedSecrets transfers every secret in projectID currently owned by
// fromOwnerID to toOwnerID, returning the number reassigned. Secrets whose individual
// transfer is unauthorized or fails are skipped (best-effort, like the project-wide
// suspend), so a partial failure does not abort the rest. The actor must satisfy the
// per-secret transfer rule for each (it does for the offboarding case: the old owner is
// gone). Each reassignment is audited as secret.owner_transferred.
//
// #G10: this had no independent authorization of its own — for the offboarding case the
// old owner is gone, so transferOwnership's per-secret rule ("actor is current owner, OR
// the current owner is gone") passed for every secret with no check on the actor's own
// relationship to the project at all, and the per-secret continue-on-error masked any
// denial that DID occur. It now requires the actor hold secrets.write at the project's
// scope up front, matching the HTTP router's own gate for this route.
func (c *KeyorixCore) ReassignOwnedSecrets(ctx context.Context, actorKind string, actorID, projectID, fromOwnerID, toOwnerID uint) (int, error) {
	if projectID == 0 || fromOwnerID == 0 || toOwnerID == 0 || actorID == 0 {
		return 0, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "project ID, from-owner, to-owner and actor ID are required")
	}
	if fromOwnerID == toOwnerID {
		return 0, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "from-owner and to-owner must differ")
	}
	if allowed, err := c.AuthorizePrincipal(ctx, actorKind, actorID, permSecretsWrite, Scope{ProjectID: projectID}); err != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	} else if !allowed {
		return 0, fmt.Errorf("%s: %s", i18n.T("ErrorPermissionDenied", nil), "not authorized to reassign secrets in this project")
	}
	// The new owner must exist (fail fast — TransferSecretOwnership re-checks per secret).
	if _, err := c.storage.GetUser(ctx, toOwnerID); err != nil {
		return 0, fmt.Errorf("%s: new owner %d not found", i18n.T("ErrorValidation", nil), toOwnerID)
	}

	secrets, err := c.listProjectSecrets(ctx, projectID)
	if err != nil {
		return 0, err
	}

	reassigned := 0
	for _, s := range secrets {
		if s.OwnerID != fromOwnerID {
			continue
		}
		// Use the primitive (no per-secret notification) — one summary is sent below.
		if _, err := c.transferOwnership(ctx, s.ID, toOwnerID, actorID); err != nil {
			continue // skip per-secret failures; keep going
		}
		reassigned++
	}
	// One "N secrets reassigned to you" notification instead of one per secret.
	c.notifySecretsReassigned(ctx, toOwnerID, actorID, projectID, reassigned)
	return reassigned, nil
}
