package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// requireActorActive refuses a mutation by a human actor whose account is no longer
// active: suspended, deprovisioned, deactivated (IsActive false) or holding an
// unrecognized state, the same rule userStillActiveForGrant applies to a step-up
// grant. #4159 (authzdiff known-02): the transports refuse a suspended account at
// authentication, but the core methods they call took the actor's roles at face
// value, so a direct core call as a suspended actor succeeded. The mutating entry
// points the authzdiff harness binds call this first, so the account state is
// checked in one place (INV-CORE-mutation-refuses-inactive-actor). It is not
// universal: ShareSecret, UpdateSharePermission, GrantSecretACL and CreateSecret do
// not call it, and a new mutating entry point must call it itself.
//
// Not checked: actorID 0 (the local/system pseudo-actor, and every machine token,
// whose UserID is 0) and a machine actor tagged on ctx (WithActorType), whose own
// lifecycle state is enforced by machine authentication, not here. A read of the
// account that fails is a refusal too (fail closed), typed as a storage read fault so
// a transport answers it 503 rather than a 403; a positive not-found (no such
// account) is a typed refusal.
func (c *KeyorixCore) requireActorActive(ctx context.Context, actorID uint) error {
	if actorID == 0 || actorTypeFromContext(ctx) == ActorTypeMachine {
		return nil
	}
	active, err := c.userStillActiveForGrant(ctx, actorID)
	if err != nil && !isPositiveNotFound(err) {
		// A read FAULT carries ErrStorageReadUnavailable, so a transport answers
		// retry (503), not a refusal or a 500 (STORAGE-ERR-CLASS-4).
		return fmt.Errorf("%s: resolving the acting account: %w", i18n.T("ErrorRetrievalFailed", nil), &storageReadFault{cause: err})
	}
	if err != nil || !active {
		return permissionDeniedf("%s: the acting account is not active", i18n.T("ErrorPermissionDenied", nil))
	}
	return nil
}

// humanActorID is actorID for a human actor and 0 (not checked) for a call the
// caller flagged as made by a machine, whose actorID is not a user ID.
func humanActorID(actorID uint, actorIsMachine bool) uint {
	if actorIsMachine {
		return 0
	}
	return actorID
}

// refuseMachineActor refuses a machine actor at a human-only core operation (its
// actor is a user: shares, ACL grants, tags, descriptions, moves, copies,
// certificate inspection, expiry extension, access requests, break-glass) with a
// typed refusal. #4162 (authzdiff known-08): a machine's UserID 0 used to fall
// through to the operation's own "actor ID is required" validation, an untyped
// error that REST answered 400 or 500 and gRPC InvalidArgument or Internal. Whether
// a machine should be allowed any of these is a separate product decision; this
// only types the refusal it already got.
func refuseMachineActor(ctx context.Context, actorID uint) error {
	if actorID == 0 && actorTypeFromContext(ctx) == ActorTypeMachine {
		return permissionDeniedf("%s: a machine identity cannot perform this operation; it needs a user account", i18n.T("ErrorPermissionDenied", nil))
	}
	return nil
}
