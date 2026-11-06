package core

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Revoking a share is allowed to the secret's owner and to a holder of
// secrets.manage at the secret's scope (the permission that already governs
// per-secret ACL revocation). Updating a share stays owner-only.

func newShareRevokeFixture(t *testing.T) (f *ctaReview, owner, recipient *models.User, secret *models.SecretNode) {
	t.Helper()
	f = newCTAReviewSQLite(t)
	owner = f.user("rev-owner", "project_developer")
	recipient = f.user("rev-recipient", "project_viewer")
	secret = f.secret("rev-secret", owner.ID)
	return
}

func (f *ctaReview) shareFor(secretID, ownerID, recipientID uint) *models.ShareRecord {
	f.t.Helper()
	sh, err := f.coreA.ShareSecret(f.ctx, &ShareSecretRequest{
		SecretID: secretID, RecipientID: recipientID, Permission: "read", SharedBy: ownerID,
	})
	require.NoError(f.t, err)
	return sh
}

func TestRevokeShare_OwnerRevokes(t *testing.T) {
	f, owner, recipient, s := newShareRevokeFixture(t)
	sh := f.shareFor(s.ID, owner.ID, recipient.ID)
	require.NoError(t, f.coreA.RevokeShare(f.ctx, sh.ID, owner.ID))
	_, err := f.coreA.Storage().GetShareRecord(f.ctx, sh.ID)
	assert.Error(t, err)
}

func TestRevokeShare_ManagerRevokesAndIsAudited(t *testing.T) {
	f, owner, recipient, s := newShareRevokeFixture(t)
	sh := f.shareFor(s.ID, owner.ID, recipient.ID)
	require.NoError(t, f.coreA.RevokeShare(f.ctx, sh.ID, f.adminID))
	_, err := f.coreA.Storage().GetShareRecord(f.ctx, sh.ID)
	assert.Error(t, err, "the share is gone")

	var desc string
	var actor uint
	row := f.setupDB.Raw(
		"SELECT description, user_id FROM audit_events WHERE event_type = ? AND secret_node_id = ? ORDER BY id DESC LIMIT 1",
		string(ShareAuditEventRevoked), s.ID).Row()
	require.NoError(t, row.Scan(&desc, &actor))
	assert.Equal(t, f.adminID, actor, "the audit row names the acting administrator")
	assert.True(t, strings.Contains(desc, "not the owner"), "the audit row says the revoker was not the owner: %q", desc)
}

// The group-share branch of the revoke audit (logGroupShareRevokedOn) carries the
// same actor and "not the owner" marker as the direct one.
func TestRevokeShare_ManagerRevokesGroupShareAndIsAudited(t *testing.T) {
	f, owner, _, s := newShareRevokeFixture(t)
	group, err := f.setup.CreateGroup(f.ctx, f.adminID, &CreateGroupRequest{Name: "rev-group"})
	require.NoError(t, err)
	viewer, err := f.setup.Storage().GetRoleByName(f.ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, f.setup.Storage().AssignRoleToGroup(f.ctx, group.ID, viewer.ID, Scope{ProjectID: f.projectID}))
	sh, err := f.coreA.ShareSecretWithGroup(f.ctx, &GroupShareSecretRequest{
		SecretID: s.ID, GroupID: group.ID, Permission: "read", SharedBy: owner.ID,
	})
	require.NoError(t, err)
	require.True(t, sh.IsGroup)

	require.NoError(t, f.coreA.RevokeShare(f.ctx, sh.ID, f.adminID))
	_, err = f.coreA.Storage().GetShareRecord(f.ctx, sh.ID)
	assert.Error(t, err, "the group share is gone")

	var desc string
	var actor uint
	row := f.setupDB.Raw(
		"SELECT description, user_id FROM audit_events WHERE event_type = ? AND secret_node_id = ? ORDER BY id DESC LIMIT 1",
		string(ShareAuditEventGroupRevoked), s.ID).Row()
	require.NoError(t, row.Scan(&desc, &actor))
	assert.Equal(t, f.adminID, actor, "the group_share_revoked row names the acting administrator")
	assert.True(t, strings.Contains(desc, "not the owner"), "the group_share_revoked row says the revoker was not the owner: %q", desc)
}

func TestRevokeShare_ProjectAdminRevokes(t *testing.T) {
	f, owner, recipient, s := newShareRevokeFixture(t)
	sh := f.shareFor(s.ID, owner.ID, recipient.ID)
	pa := f.user("rev-project-admin", "project_admin")
	require.NoError(t, f.coreA.RevokeShare(f.ctx, sh.ID, pa.ID))
}

func TestRevokeShare_MachineActorRefused(t *testing.T) {
	f, owner, recipient, s := newShareRevokeFixture(t)
	sh := f.shareFor(s.ID, owner.ID, recipient.ID)
	err := f.coreA.RevokeShare(f.ctx, sh.ID, 0)
	require.Error(t, err)
	_, gerr := f.coreA.Storage().GetShareRecord(f.ctx, sh.ID)
	assert.NoError(t, gerr, "the share is untouched")
}

func TestRevokeShare_NonManagerNonOwnerRefused(t *testing.T) {
	f, owner, recipient, s := newShareRevokeFixture(t)
	sh := f.shareFor(s.ID, owner.ID, recipient.ID)
	// Neither a developer nor a viewer holds secrets.manage (and neither bypasses
	// permission checks the way an admin role does).
	for _, role := range []string{"project_developer", "project_viewer"} {
		other := f.user("rev-other-"+role, role)
		err := f.coreA.RevokeShare(f.ctx, sh.ID, other.ID)
		require.Error(t, err, role)
		assert.True(t, errors.Is(err, ErrShareNotOwner), "%s: %v", role, err)
	}
	_, err := f.coreA.Storage().GetShareRecord(f.ctx, sh.ID)
	assert.NoError(t, err, "the share is untouched")
}

func TestUpdateSharePermission_ManagerStillRefused(t *testing.T) {
	f, owner, recipient, s := newShareRevokeFixture(t)
	sh := f.shareFor(s.ID, owner.ID, recipient.ID)
	_, err := f.coreA.UpdateSharePermission(f.ctx, &UpdateShareRequest{
		ShareID: sh.ID, Permission: "write", UpdatedBy: f.adminID,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareNotOwner), "%v", err)
}

// requireRevokeRefused asserts actorID's revoke on ctx is refused with
// ErrShareNotOwner and leaves the share in place.
func (f *ctaReview) requireRevokeRefused(ctx context.Context, shareID, actorID uint, why string) {
	f.t.Helper()
	err := f.coreA.RevokeShare(ctx, shareID, actorID)
	require.Error(f.t, err, why)
	assert.True(f.t, errors.Is(err, ErrShareNotOwner), "%s: %v", why, err)
	_, gerr := f.coreA.Storage().GetShareRecord(f.ctx, shareID)
	assert.NoError(f.t, gerr, "%s: the share is untouched", why)
}

// grantAt gives userID roleName at scope.
func (f *ctaReview) grantAt(userID uint, roleName string, scope Scope) {
	f.t.Helper()
	role, err := f.setup.Storage().GetRoleByName(f.ctx, roleName)
	require.NoError(f.t, err)
	require.NoError(f.t, f.setup.Storage().AssignRole(f.ctx, userID, role.ID, scope))
}

// The administrator check runs at the secret's own project/environment: an
// administrator of another project, or one scoped to another environment of the
// same project, is refused. The admin scoped to the secret's own environment is
// the control showing an environment-scoped role is honoured at all.
func TestRevokeShare_AdminOfOtherScopeRefused(t *testing.T) {
	f, owner, recipient, s := newShareRevokeFixture(t)
	sh := f.shareFor(s.ID, owner.ID, recipient.ID)

	otherProj, err := f.setup.CreateProject(f.ctx, "rev-other-project", "")
	require.NoError(t, err)
	otherEnv, err := f.setup.CreateEnvironment(f.ctx, f.projectID, "rev-other-env")
	require.NoError(t, err)

	elsewhere := f.user("rev-admin-other-project", "")
	f.grantAt(elsewhere.ID, "project_admin", Scope{ProjectID: otherProj.ID})
	f.requireRevokeRefused(f.ctx, sh.ID, elsewhere.ID, "project_admin of another project")

	otherEnvAdmin := f.user("rev-admin-other-env", "")
	f.grantAt(otherEnvAdmin.ID, "project_admin", Scope{ProjectID: f.projectID, EnvironmentID: otherEnv.ID})
	f.requireRevokeRefused(f.ctx, sh.ID, otherEnvAdmin.ID, "project_admin of another environment of the same project")

	sameEnvAdmin := f.user("rev-admin-same-env", "")
	f.grantAt(sameEnvAdmin.ID, "project_admin", Scope{ProjectID: f.projectID, EnvironmentID: f.envID})
	require.NoError(t, f.coreA.RevokeShare(f.ctx, sh.ID, sameEnvAdmin.ID), "project_admin of the secret's own environment")
	_, err = f.coreA.Storage().GetShareRecord(f.ctx, sh.ID)
	assert.Error(t, err, "the share is gone")
}

// The administrator check goes through Authorize, so the caller's PAT narrows it
// (even the system admin's bypass): a token without secrets.manage, or confined
// to another project, cannot use the administrator path. The unrestricted and
// the same-project tokens are the controls.
func TestRevokeShare_PATNarrowsAdministratorPath(t *testing.T) {
	f, owner, recipient, s := newShareRevokeFixture(t)
	otherProj, err := f.setup.CreateProject(f.ctx, "rev-pat-other-project", "")
	require.NoError(t, err)

	sh := f.shareFor(s.ID, owner.ID, recipient.ID)
	readWrite := WithPATRestriction(f.ctx, &PATRestriction{Permissions: []string{permSecretsRead, permSecretsWrite}})
	f.requireRevokeRefused(readWrite, sh.ID, f.adminID, "system admin under a PAT allowing only secrets.read+write")
	confined := WithPATRestriction(f.ctx, &PATRestriction{ProjectID: otherProj.ID})
	f.requireRevokeRefused(confined, sh.ID, f.adminID, "system admin under a PAT confined to another project")

	here := WithPATRestriction(f.ctx, &PATRestriction{ProjectID: f.projectID, Permissions: []string{"secrets.*"}})
	require.NoError(t, f.coreA.RevokeShare(here, sh.ID, f.adminID), "system admin under a PAT for this project and secrets.*")
	_, err = f.coreA.Storage().GetShareRecord(f.ctx, sh.ID)
	assert.Error(t, err, "the share is gone")
}

// The administrator check is role-based only: secrets.manage held through a
// per-secret ACL does not qualify. The row is written directly because
// GrantSecretACL only hands out read/write; HasSecretACL honouring it is the
// premise that makes the refusal meaningful.
func TestRevokeShare_ACLManageDoesNotQualify(t *testing.T) {
	f, owner, recipient, s := newShareRevokeFixture(t)
	sh := f.shareFor(s.ID, owner.ID, recipient.ID)

	holder := f.user("rev-acl-holder", "project_viewer")
	perms, err := EncodeSecretACLPerms([]string{permSecretsRead, permSecretsWrite, permSecretsManage})
	require.NoError(t, err)
	require.NoError(t, f.setupDB.Create(&models.SecretACL{
		SecretID: s.ID, UserID: holder.ID, Permissions: perms, GrantedBy: f.adminID,
	}).Error)
	has, err := f.coreA.HasSecretACL(f.ctx, holder.ID, s.ID, permSecretsManage)
	require.NoError(t, err)
	require.True(t, has, "premise: the ACL path grants the holder secrets.manage on this secret")

	f.requireRevokeRefused(f.ctx, sh.ID, holder.ID, "secrets.manage through a per-secret ACL")
}

// A role-lookup error in the administrator check fails closed: the revoke
// returns the error (not a refusal the caller could retry around, and never a
// revoke) and the share stays. The revoker is a project_admin, who would be
// allowed without the fault.
func TestRevokeShare_AdminLookupErrorFailsClosed(t *testing.T) {
	f, owner, recipient, s := newShareRevokeFixture(t)
	sh := f.shareFor(s.ID, owner.ID, recipient.ID)
	pa := f.user("rev-lookup-admin", "project_admin")

	faulty := faultstorage.NewFaultyStorage(f.coreA.storage, nil)
	f.coreA.storage = faulty
	faulty.Arm(&faultstorage.FaultSpec{Method: "ResolveUserPermissionAt", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})

	err := f.coreA.RevokeShare(f.ctx, sh.ID, pa.ID)
	require.Error(t, err)
	assert.True(t, errors.Is(err, assert.AnError), "the lookup error is returned: %v", err)
	assert.False(t, errors.Is(err, ErrShareNotOwner), "a lookup error is not reported as a refusal: %v", err)
	_, gerr := f.coreA.Storage().GetShareRecord(f.ctx, sh.ID)
	assert.NoError(t, gerr, "the share is untouched")
}

// After an ownership transfer the previous owner has no owner authority left;
// when they administer the secret's scope they may still revoke (as an
// administrator, audited as not the owner), but not update.
func TestRevokeShare_AdminPreviousOwnerRevokesAfterTransfer(t *testing.T) {
	f := newCTAReviewSQLite(t)
	oldOwner := f.user("rev-admin-old-owner", "project_admin")
	newOwner := f.user("rev-new-owner", "project_developer")
	recipient := f.user("rev-transfer-recipient", "project_viewer")
	s := f.secret("rev-transfer-secret", oldOwner.ID)
	sh := f.shareFor(s.ID, oldOwner.ID, recipient.ID)

	_, err := f.coreA.TransferSecretOwnership(f.ctx, s.ID, newOwner.ID, oldOwner.ID, ActorTypeUser)
	require.NoError(t, err)

	_, err = f.coreA.UpdateSharePermission(f.ctx, &UpdateShareRequest{ShareID: sh.ID, Permission: "write", UpdatedBy: oldOwner.ID})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareNotOwner), "admin previous owner must not update: %v", err)

	require.NoError(t, f.coreA.RevokeShare(f.ctx, sh.ID, oldOwner.ID), "admin previous owner may revoke")
	_, err = f.coreA.Storage().GetShareRecord(f.ctx, sh.ID)
	assert.Error(t, err, "the share is gone")

	var desc string
	var actor uint
	row := f.setupDB.Raw(
		"SELECT description, user_id FROM audit_events WHERE event_type = ? AND secret_node_id = ? ORDER BY id DESC LIMIT 1",
		string(ShareAuditEventRevoked), s.ID).Row()
	require.NoError(t, row.Scan(&desc, &actor))
	assert.Equal(t, oldOwner.ID, actor)
	assert.True(t, strings.Contains(desc, "not the owner"), "revoked as an administrator, not as the owner: %q", desc)
}
