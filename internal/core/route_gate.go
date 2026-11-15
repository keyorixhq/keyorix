package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

// Route-gate permissions enforced in core (#4161, authzdiff known-04).
//
// The REST route groups and the gRPC methods check a permission before they call
// a core entry point (the /roles group's roles.read, the /groups and /users
// groups' users.read, a per-secret secrets.write, ...). On the entry points
// below core did not check that permission itself, so a direct core call (or a
// future transport) that skipped the gate succeeded where both transports
// refuse. Each entry point now calls its family's gate first, so REST, gRPC and
// any other caller get the same answer from core
// (INV-CORE-route-gate-permission-in-core). The transport gates stay in place
// (defence in depth); a refusal is typed ErrPermissionDenied (403 /
// PermissionDenied), a failed lookup a storage read fault (503 / Unavailable).
//
// The acting principal is the one the transports tag on ctx: a machine identity
// when ctx carries ActorTypeMachine (its ID from WithMachineActor; the actorID
// argument is 0 or the machine's own ID depending on the transport, so it is
// not used), otherwise the human user actorID. actorID 0 without a machine tag
// is the trusted local/system pseudo-actor (intended difference ID-1:
// schedulers, reconcilers and setup flows that run with no acting user) and is
// not checked, as everywhere else in core.

// actingPrincipal returns the principal kind and ID a route gate is decided
// for. system is true for the trusted actorID-0 pseudo-actor. A ctx tagged as a
// machine without a machine ID is refused (fail closed): that is a caller bug,
// never the system actor.
func actingPrincipal(ctx context.Context, actorID uint) (kind string, id uint, system bool, err error) {
	if actorTypeFromContext(ctx) == ActorTypeMachine {
		mid, ok := machineActorFromContext(ctx)
		if !ok {
			return "", 0, false, permissionDeniedf("%s: the acting machine identity is not known", i18n.T("ErrorPermissionDenied", nil))
		}
		return ActorTypeMachine, mid, false, nil
	}
	if actorID == 0 {
		return "", 0, true, nil
	}
	return ActorTypeUser, actorID, false, nil
}

// requireActorPermissions refuses unless the acting principal holds every one of
// perms at scope. It is the one primitive the family gates below share.
func (c *KeyorixCore) requireActorPermissions(ctx context.Context, actorID uint, scope Scope, perms ...string) error {
	kind, id, system, err := actingPrincipal(ctx, actorID)
	if err != nil || system {
		return err
	}
	for _, perm := range perms {
		allowed, aerr := c.AuthorizePrincipal(ctx, kind, id, perm, scope)
		if aerr != nil {
			return fmt.Errorf("%s: resolving the actor's %s: %w", i18n.T("ErrorRetrievalFailed", nil), perm, &storageReadFault{cause: aerr})
		}
		if !allowed {
			return permissionDeniedf("%s: %s is required", i18n.T("ErrorPermissionDenied", nil), perm)
		}
	}
	return nil
}

// requireSecretGate is the per-secret secrets.write gate of the /secrets/{id}
// routes (RequireScopedSecretPermission) and the gRPC SecretService
// (authorizeSecretScoped): an ACL grant, a role at the secret's scope, or a share
// that action may be elevated by — and, unlike checkSecretPermission alone, NOT
// ownership by itself: an owner whose roles do not grant secrets.write is refused,
// as both gates refuse them. A machine takes the role-only path, as in the gates.
//
// A human actor is decided by checkSecretPermission (it needs no request
// recorder to honour an allowlisted write share, unlike AuthorizeSecretAction),
// and an owner-sourced grant is re-decided without the owner pass.
func (c *KeyorixCore) requireSecretGate(ctx context.Context, actorID, secretID uint, action SecretAction) error {
	kind, id, system, err := actingPrincipal(ctx, actorID)
	if err != nil || system {
		return err
	}
	if kind == ActorTypeMachine {
		secret, gerr := c.storage.GetSecret(ctx, secretID)
		if gerr != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), classifySecretGateRead(gerr))
		}
		d, aerr := c.AuthorizeSecretPrincipalForSecretAction(ctx, kind, id, secret, permSecretsWrite, action)
		return secretGateDecision(d, aerr)
	}
	pc, secret, err := c.checkSecretPermission(ctx, secretID, id, PermissionWrite, action)
	if err != nil {
		return err
	}
	if pc.Source != "owner" {
		return nil
	}
	d, aerr := c.AuthorizeSecretAction(ctx, id, secretID, permSecretsWrite, action, secret)
	return secretGateDecision(d, aerr)
}

// classifySecretGateRead keeps a positive not-found as is and marks any other
// failure as a storage read fault.
func classifySecretGateRead(err error) error {
	if isPositiveNotFound(err) {
		return err
	}
	return &storageReadFault{cause: err}
}

func secretGateDecision(d SecretDecision, err error) error {
	switch {
	case err != nil:
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), classifySecretGateRead(err))
	case d.Allowed:
		return nil
	case d.ShareNotElevated:
		return shareRefusal(ErrShareActionNotElevated)
	}
	return permissionDeniedf("%s: insufficient permissions", i18n.T("ErrorPermissionDenied", nil))
}

// requireSecretScopeGate is the shares family's gate: PUT/DELETE /shares/{id} and
// the gRPC ShareService require secrets.write at the shared secret's scope
// (ScopeFromShareParam), on top of the owner/manager rule core already applies.
func (c *KeyorixCore) requireSecretScopeGate(ctx context.Context, actorID, projectID, environmentID uint) error {
	return c.requireActorPermissions(ctx, actorID, Scope{ProjectID: projectID, EnvironmentID: environmentID}, permSecretsWrite)
}

// requireEnvironmentCopyGate is the environments family's gate for clone and
// copy-secrets: secrets.write on the project (the copies are created there) and
// secrets.read on the source environment (their values are read).
func (c *KeyorixCore) requireEnvironmentCopyGate(ctx context.Context, actorID, projectID, sourceEnvID uint) error {
	if err := c.requireActorPermissions(ctx, actorID, Scope{ProjectID: projectID}, permSecretsWrite); err != nil {
		return err
	}
	return c.requireActorPermissions(ctx, actorID, Scope{ProjectID: projectID, EnvironmentID: sourceEnvID}, permSecretsRead)
}

// requireRoleAdminGate is the roles family's gate: the /roles route group's
// roles.read plus the mutating routes' roles.write, both install-wide.
func (c *KeyorixCore) requireRoleAdminGate(ctx context.Context, actorID uint) error {
	return c.requireActorPermissions(ctx, actorID, Scope{}, permRolesRead, "roles.write")
}

// requireActorHoldsRolePermissions is the roles family's bundling rule for a
// role's new permission set: the REST and gRPC update handlers
// (resolveAndAuthorizePermissions, resolvePermissionIDs) refuse an actor who does
// not hold every permission of the set install-wide, so a role can never be made
// to carry a permission its editor lacks.
func (c *KeyorixCore) requireActorHoldsRolePermissions(ctx context.Context, actorID uint, permissionIDs []uint) error {
	for _, id := range permissionIDs {
		perm, err := c.storage.GetPermission(ctx, id)
		if err != nil {
			return fmt.Errorf("%s: permission %d: %w", i18n.T("ErrorRetrievalFailed", nil), id, classifySecretGateRead(err))
		}
		if err := c.requireActorPermissions(ctx, actorID, Scope{}, perm.Name); err != nil {
			return err
		}
	}
	return nil
}

// requireUserAdminGate is the users family's gate for creating an account: the
// /users route group's users.read plus users.write, both install-wide.
func (c *KeyorixCore) requireUserAdminGate(ctx context.Context, actorID uint) error {
	return c.requireActorPermissions(ctx, actorID, Scope{}, permUsersRead, permUsersWrite)
}

// requireIdentityGrantGate is the gate of the routes that change what an identity
// holds through the /groups and /users route groups (group restore, group role
// assignment, group member add, a user's role set): the group's users.read plus
// the route's roles.assign, both install-wide.
func (c *KeyorixCore) requireIdentityGrantGate(ctx context.Context, actorID uint) error {
	return c.requireActorPermissions(ctx, actorID, Scope{}, permUsersRead, permRolesAssign)
}

// requireProjectRestoreGate is the projects family's gate: POST
// /projects/{id}/restore requires roles.assign at the project.
func (c *KeyorixCore) requireProjectRestoreGate(ctx context.Context, actorID, projectID uint) error {
	return c.requireActorPermissions(ctx, actorID, Scope{ProjectID: projectID}, permRolesAssign)
}

// requireGlobalInvitationGate is the invitations family's gate: POST
// /invitations requires install-wide users.write.
func (c *KeyorixCore) requireGlobalInvitationGate(ctx context.Context, actorID uint) error {
	return c.requireActorPermissions(ctx, actorID, Scope{}, permUsersWrite)
}

// requireBulkApprovalGate is the approvals family's gate: POST
// /access-requests/bulk-approve requires install-wide roles.assign before the
// per-item roles.assign at each request's project.
func (c *KeyorixCore) requireBulkApprovalGate(ctx context.Context, actorID uint) error {
	return c.requireActorPermissions(ctx, actorID, Scope{}, permRolesAssign)
}
