// share_authz.go — the share term of every per-secret authorization decision (#2941).
//
// Decision (Andrei, 2026-10-10, #2941): a share MAY elevate a project member's access
// on that one secret. A member's effective permission on a secret is
//
//	max(role permission, active share permission)
//
// where "active share permission" is the highest level any direct share to the user,
// or group share to a group the user belongs to (scoped to the secret's project),
// grants — with four limits, each enforced here and nowhere else:
//
//  1. Shares never apply to a non-member. The recipient must be a live member of the
//     secret's project (IsProjectMember) at ACCESS time, not only when the share was
//     created: RemoveProjectMember deletes role grants and ACLs but not share rows, so
//     without this a removed member's leftover share would become their only grant.
//  2. Expired shares grant nothing (shareActive), even before the sweeper reclaims the
//     row. A revoked share is a deleted row, so it grants nothing by construction.
//  3. A share grants only what its level says: read → secrets.read, write →
//     secrets.read + secrets.write. Never secrets.delete, secrets.manage, owner, or the
//     right to share (ShareSecret's owner gate is separate). A level outside read|write
//     (a corrupt row) grants nothing.
//  4. Machine identities never take this path: share recipients are user IDs, and a
//     machine principal's ID lives in a different ID space (see
//     AuthorizeSecretPrincipal).
//
// Both decision functions use sharePermissionFor: AuthorizeSecret (the gate every
// per-secret HTTP route, gRPC RPC and core helper consults) and CheckSecretPermission
// (the core *WithPermissionCheck paths). share_authz_guard_test.go fails the build if
// either stops calling it, or if a transport's per-secret gate stops calling
// AuthorizeSecret.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ShareAuditEventAccessElevated records an action a share authorized that the
// actor's role (and any ACL) alone would not have: the decision's share id, the
// permission exercised and the share's level.
const ShareAuditEventAccessElevated ShareAuditEvent = "share_access_elevated"

// Typed refusals for share management (#2976: every one of these used to surface as
// a bare "Not authorized to share this secret"). Each wraps the i18n
// ErrorPermissionDenied text, so every existing "permission denied" → 403 /
// PermissionDenied mapping still applies; ShareRefusalMessage gives transports the
// user-facing reason.
var (
	// ErrShareNotOwner: only the secret's owner may share it or change its shares.
	ErrShareNotOwner = errors.New("not authorized: only the secret's owner can share it")
	// ErrShareOwnerNotMember: the actor owns the secret but is not a live member of
	// its project (RBAC-001). A global role makes nobody a member of any project.
	ErrShareOwnerNotMember = errors.New("not authorized: the owner is not a member of the secret's project")
	// ErrShareRecipientNotMember: shares never apply to non-members.
	ErrShareRecipientNotMember = errors.New("not authorized: the recipient is not a member of the secret's project")
	// ErrShareGroupNotInProject: the recipient group holds no role in the secret's
	// project.
	ErrShareGroupNotInProject = errors.New("not authorized: the recipient group has no role in the secret's project")
)

// shareRefusal wraps a share-management sentinel so it reads as a permission denial
// to every existing string-matching mapper and as the sentinel to errors.Is.
func shareRefusal(sentinel error) error {
	return fmt.Errorf("%s: %w", i18n.T("ErrorPermissionDenied", nil), sentinel)
}

// ShareRefusalMessage returns the fixed, user-facing explanation for a share
// management refusal, and false for any other error. HTTP and gRPC both use it so the
// two transports say the same thing. Never echoes err itself.
func ShareRefusalMessage(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrShareOwnerNotMember):
		return "You own this secret but you are not a member of this secret's project, and only a project member can share it. " +
			"Ask a project admin to give you a role in the project (for example project_admin), then share again.", true
	case errors.Is(err, ErrShareRecipientNotMember):
		return "The recipient is not a member of this secret's project. Shares only apply to project members: " +
			"give them a role in the project first (for example project_viewer), then share again.", true
	case errors.Is(err, ErrShareGroupNotInProject):
		return "The recipient group has no role in this secret's project. Shares only apply to project members: " +
			"give the group a role in the project first, then share again.", true
	case errors.Is(err, ErrShareNotOwner):
		return "Only the secret's owner can share it or change its shares.", true
	}
	return "", false
}

// requireShareAuthority is the owner gate of every share mutation (ShareSecret,
// ShareSecretWithGroup, UpdateSharePermission, RevokeShare): actorID must own the
// secret AND be a live member of its project (requireLiveOwnerAuthority, RBAC-001).
// Returns a typed refusal saying which half failed.
func (c *KeyorixCore) requireShareAuthority(ctx context.Context, secret *models.SecretNode, actorID uint) error {
	if !secretOwnedBy(secret.OwnerID, actorID) {
		return shareRefusal(ErrShareNotOwner)
	}
	isLiveOwner, err := c.requireLiveOwnerAuthority(ctx, secret, actorID)
	if err != nil {
		return err
	}
	if !isLiveOwner {
		return shareRefusal(ErrShareOwnerNotMember)
	}
	return nil
}

// shareGrant is the outcome of sharePermissionFor.
type shareGrant struct {
	Level   PermissionLevel // PermissionNone, PermissionRead or PermissionWrite
	ShareID *uint
	Source  string // "direct_share" or "group_share"
}

// shareLevel maps a stored share permission to the level it grants. Only read and
// write exist (ShareSecretRequest validates oneof=read write); anything else grants
// nothing, so a corrupt row can never read as owner (hasRequiredPermission would
// otherwise rank a literal "owner" above write).
func shareLevel(stored string) PermissionLevel {
	switch PermissionLevel(stored) {
	case PermissionRead:
		return PermissionRead
	case PermissionWrite:
		return PermissionWrite
	}
	return PermissionNone
}

// sharePermissionFor returns the active share that grants userID at least need on
// secret secretID (which lives in project projectID), or a PermissionNone grant when
// none does (see the file header for the limits). Direct shares are consulted first,
// then group shares (CheckGroupPermissions); a group-membership lookup failure counts
// as "no group grant" — the share term can only ever ADD access, so failing to
// evaluate it denies the elevation and leaves the caller's role/ACL decision as it
// was. Any other storage error fails closed with (none, err).
func (c *KeyorixCore) sharePermissionFor(ctx context.Context, userID, secretID, projectID uint, need PermissionLevel) (shareGrant, error) {
	none := shareGrant{Level: PermissionNone}
	if userID == 0 {
		return none, nil
	}
	shares, err := c.storage.ListSharesBySecret(ctx, secretID, c.shareEffectiveNow())
	if err != nil {
		return none, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	// Drop expired (time-bound) shares before any authorization: an expired share
	// must never grant access, even though the sweep that reclaims its row runs later.
	shares = activeShares(shares, c.shareEffectiveNow())

	grant := none
	for _, share := range shares {
		if share.IsGroup || share.RecipientID != userID {
			continue
		}
		if lvl := shareLevel(share.Permission); c.hasRequiredPermission(lvl, need) {
			id := share.ID
			grant = shareGrant{Level: lvl, ShareID: &id, Source: "direct_share"}
			break
		}
	}
	if grant.Level == PermissionNone {
		groupLevel, groupShareID, gerr := c.CheckGroupPermissions(ctx, secretID, userID, shares, projectID)
		if gerr != nil {
			log.Printf("share authorization: group-share lookup failed (user_id=%d secret_id=%d); no group share applies: %v", userID, secretID, gerr)
		} else if lvl := shareLevel(string(groupLevel)); c.hasRequiredPermission(lvl, need) {
			grant = shareGrant{Level: lvl, ShareID: groupShareID, Source: "group_share"}
		}
	}
	if grant.Level == PermissionNone {
		return none, nil
	}

	// Shares never apply to a non-member — checked last so a caller with no
	// covering share pays no membership lookup.
	member, err := c.IsProjectMember(ctx, userID, projectID)
	if err != nil {
		return none, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if !member {
		return none, nil
	}
	return grant, nil
}

// shareNeedFor maps an RBAC permission to the share level that would satisfy it.
// Only secrets.read and secrets.write can ever be satisfied by a share; every other
// permission (secrets.delete, secrets.manage, roles.assign, ...) maps to
// PermissionNone, which sharePermissionFor never grants.
func shareNeedFor(perm string) PermissionLevel {
	switch perm {
	case permSecretsRead:
		return PermissionRead
	case permSecretsWrite:
		return PermissionWrite
	}
	return PermissionNone
}

// shareElevationDetail is the structured payload of a share_access_elevated event.
type shareElevationDetail struct {
	ShareID         uint   `json:"share_id"`
	Permission      string `json:"permission"`
	SharePermission string `json:"share_permission"`
	Source          string `json:"source"`
}

// auditShareElevation records that grant (not the actor's role or ACL) authorized
// perm on secret. Best-effort like every other audit write: the authorization
// decision has already been made.
func (c *KeyorixCore) auditShareElevation(ctx context.Context, userID uint, secret *models.SecretNode, perm string, grant shareGrant) {
	if grant.ShareID == nil {
		return
	}
	detail, _ := json.Marshal(shareElevationDetail{
		ShareID: *grant.ShareID, Permission: perm, SharePermission: string(grant.Level), Source: grant.Source,
	})
	uid, sid, pid := userID, secret.ID, secret.ProjectID
	desc := fmt.Sprintf("%s on secret %d authorized by share %d (%s, %s); the actor's role alone does not grant it",
		perm, secret.ID, *grant.ShareID, grant.Source, grant.Level)
	c.writeAuditEventDiff(ctx, string(ShareAuditEventAccessElevated), &uid, &sid, &pid, "", desc, string(detail))
}
