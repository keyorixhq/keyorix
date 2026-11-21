// authz_core_gate.go — the core-side counterpart of the transports' route gates.
//
// #4161 (authzdiff waiver known-04): on about twenty operations core performed no
// (or a narrower) permission check of its own and relied on the REST route gate or
// the gRPC interceptor as the only gate. Every present transport refused the cases,
// so nothing was reachable from a client; but a core entry point that any caller
// (a future transport, a /system relay, the CLI's local mode) can drive directly is
// an authorization layer only if it decides for itself. These helpers make the same
// decision the transports make — RequirePermission / RequireScopedPermission
// (requireScopedGate) and RequireScopedSecretPermission (requireSecretActionGate)
// — from the actor the context identifies, so core denies where the transports deny
// and the strict differential sweep needs no waiver for the shape.
package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// gateActor resolves the acting principal for a core-side permission gate.
//
// A machine actor is identified by the machine identity the auth middleware tagged
// on ctx (WithMachineActor), never by actorID: a machine has no UserID (ADR-030),
// the transports pass 0 and the differential harness passes the machine ID, so
// actorID carries no reliable meaning for a machine. A machine-typed context with
// no machine ID cannot be authorized and fails closed.
//
// A human actorID of 0 is the trusted internal pseudo-actor (bootstrap, schedulers,
// reconcilers, a bulk operation not yet threading a per-item actor) that every
// existing core ceiling exempts (requireGranterHoldsRolePermissions,
// requireBaselineRoleGrantAuthority, AssignPermissionToRole's self-permission
// check); it is exempt here for the same reason. Every transport sets a real actor
// on a human request, so a client never reaches a gate as actor 0.
func gateActor(ctx context.Context, actorID uint) (actorType string, principalID uint, exempt bool, err error) {
	if actorTypeFromContext(ctx) == ActorTypeMachine {
		machineID, ok := machineActorFromContext(ctx)
		if !ok {
			return "", 0, false, permissionDeniedf("%s: the acting machine identity is not identified", i18n.T("ErrorPermissionDenied", nil))
		}
		return ActorTypeMachine, machineID, false, nil
	}
	if actorID == 0 {
		return ActorTypeUser, 0, true, nil
	}
	return ActorTypeUser, actorID, false, nil
}

// gateResolutionError classifies a failed authorization read the way
// requireOwnerHoldsGatePermission does: a role/ACL read FAULT answers retry (503),
// not a 500; a positive not-found or an already-typed error keeps its class
// (STORAGE-ERR-CLASS-4).
func gateResolutionError(err error) error {
	if !isPositiveNotFound(err) && !errors.Is(err, ErrStorageReadUnavailable) && !errors.Is(err, ErrPermissionDenied) {
		err = &storageReadFault{cause: err}
	}
	return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
}

// requireScopedGate refuses unless the acting principal holds perm at scope through
// its roles (a PAT restriction narrows it, a machine resolves its own machine roles,
// an admin-bypass role passes a human): the decision RequirePermission (scope
// global) and RequireScopedPermission make at the transports. The refusal is typed
// (ErrPermissionDenied) with the message every other core refusal of this kind uses.
func (c *KeyorixCore) requireScopedGate(ctx context.Context, actorID uint, perm string, scope Scope) error {
	actorType, principalID, exempt, err := gateActor(ctx, actorID)
	if err != nil || exempt {
		return err
	}
	ok, err := c.AuthorizePrincipal(ctx, actorType, principalID, perm, scope)
	if err != nil {
		return gateResolutionError(err)
	}
	if !ok {
		return permissionDeniedf("%s: insufficient permissions", i18n.T("ErrorPermissionDenied", nil))
	}
	return nil
}

// requireScopedGates is requireScopedGate for several (perm, scope) pairs, all of
// which must hold — a route that stacks RequireScopedPermission middlewares.
func (c *KeyorixCore) requireScopedGates(ctx context.Context, actorID uint, gates ...scopedGate) error {
	for _, g := range gates {
		if err := c.requireScopedGate(ctx, actorID, g.perm, g.scope); err != nil {
			return err
		}
	}
	return nil
}

// scopedGate is one (permission, scope) requirement of requireScopedGates.
type scopedGate struct {
	perm  string
	scope Scope
}

// permRolesWrite gates role definitions (create, update, delete, permission
// changes) at the /roles route group and the gRPC role service.
const permRolesWrite = "roles.write"

// requireActorHoldsPermissions refuses unless the acting principal itself holds,
// at the global scope, every permission in permissionIDs: the #169 rule the
// transports apply before a role update (CreateRole/UpdateRole handlers and the
// gRPC role service pre-authorize each permission being granted) and
// AssignPermissionToRole applies in core — a role author cannot bundle a permission
// they do not hold. A permission that does not exist is reported as not found, as
// the transports do; any other failure of that read is classified like the role
// reads (gateResolutionError), so a read fault answers retry, not not-found.
func (c *KeyorixCore) requireActorHoldsPermissions(ctx context.Context, actorID uint, permissionIDs []uint) error {
	actorType, principalID, exempt, err := gateActor(ctx, actorID)
	if err != nil || exempt {
		return err
	}
	for _, id := range permissionIDs {
		perm, err := c.storage.GetPermission(ctx, id)
		if err != nil {
			if isPositiveNotFound(err) || errors.Is(err, storage.ErrPermissionNotFound) {
				return fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
			}
			return gateResolutionError(err)
		}
		ok, err := c.AuthorizePrincipal(ctx, actorType, principalID, perm.Name, Scope{})
		if err != nil {
			return gateResolutionError(err)
		}
		if !ok {
			return permissionDeniedf("cannot grant permission %q to a role: you do not hold it yourself", perm.Name)
		}
	}
	return nil
}

// requireSecretActionGate refuses unless the acting principal may perform action on
// secret under perm: a per-secret ACL, a role at the secret's scope, or (a human
// only) an active share that elevates this action — the decision
// RequireScopedSecretPermission(perm, "id", action) makes at the REST router and the
// gRPC secret services make before calling core. No owner pass: ownership alone is
// not a route-gate decision (INV-CORE-secret-owner-mutation-needs-gate-permission).
// A share that covers perm but not action answers the share refusal, so a caller
// can be told why (ShareRefusalMessage), as the transports do.
func (c *KeyorixCore) requireSecretActionGate(ctx context.Context, actorID uint, secret *models.SecretNode, perm string, action SecretAction) error {
	actorType, principalID, exempt, err := gateActor(ctx, actorID)
	if err != nil || exempt {
		return err
	}
	d, err := c.AuthorizeSecretPrincipalForSecretAction(ctx, actorType, principalID, secret, perm, action)
	if err != nil {
		return gateResolutionError(err)
	}
	if d.Allowed {
		return nil
	}
	if d.ShareNotElevated {
		return shareRefusal(ErrShareActionNotElevated)
	}
	return permissionDeniedf("%s: insufficient permissions", i18n.T("ErrorPermissionDenied", nil))
}
