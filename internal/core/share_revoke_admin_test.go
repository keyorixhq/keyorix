package core

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
